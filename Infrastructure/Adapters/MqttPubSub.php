<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Infrastructure\Adapters;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\Topic;

/**
 * MQTT as the kernel's {@see PubSubPort}.
 *
 * The two halves of this class are shaped by the two halves of the port
 * contract, and they pull in opposite directions.
 *
 * `publish()` MUST NOT THROW — AND THAT IS NOT POLITENESS
 * ------------------------------------------------------
 * It is called from inside a request, to announce something that has already
 * been committed. The row is written, the payment is taken, the response is
 * owed. A broker outage at that moment must cost the notification and nothing
 * else: an exception would turn "the realtime update is late" into a 500 on an
 * operation that already succeeded, which is strictly worse than the problem.
 *
 * So every failure here is caught, logged once with the reason, and reported as
 * `-1`.
 *
 * A DEAD BROKER MUST NOT COST EVERY REQUEST THE CONNECT TIMEOUT
 * -------------------------------------------------------------
 * The naive lazy connection is the expensive bug. The broker goes down; every
 * request that publishes an event now dials a host that is not answering and
 * waits out `MQTT_CONNECT_TIMEOUT` before giving up. At the 5-second default, a
 * page that raises three events has just become a 15-second page — and under
 * PHP-FPM, where no connection survives the request, that is EVERY request, so
 * the pool fills with processes blocked in `connect()` and the site is down. The
 * bus being optional stopped being true at exactly the moment it broke.
 *
 * {@see self::$silentUntil} is the fix: after a failed connect, publishes
 * short-circuit to `-1` for a cooldown without touching the network. The cost
 * of a dead broker becomes one timeout per cooldown per process instead of one
 * per publish.
 *
 * `subscribe()` IS THE OPPOSITE: IT THROWS, LOUDLY
 * -----------------------------------------------
 * It is the server's main loop. It reconnects — with backoff and jitter, and
 * replaying its subscriptions — and when the attempts run out it throws,
 * because a subscriber that quietly stopped listening is indistinguishable from
 * a system where nothing is happening.
 *
 * ONE RECONNECT CAUSE IS NOT RETRIED, AND THAT IS SPECIFIC TO MQTT
 * ---------------------------------------------------------------
 * `0x8E Session taken over` means another process connected with the same
 * client identifier. Retrying evicts that process, which reconnects and evicts
 * this one, for ever — two processes alternating, each looking like a flapping
 * connection, neither holding a usable subscription.
 *
 * So {@see \Plugins\Mqtt\Domain\ServerDisconnect::retryWouldWorsen()} is
 * consulted and the loop gives up immediately with an error that names the
 * cause. This is the one place where failing faster is the safer behaviour, and
 * it only works because MQTT 5.0 says WHY it disconnected — a 3.1.1 broker just
 * closes the socket and the same situation is indistinguishable from a network
 * fault.
 *
 * CHANNEL NAMES ARE TRANSLATED, AND THE REASON IS WILDCARDS
 * --------------------------------------------------------
 * The kernel's channels are dotted (`documents.42`); MQTT's topics are slashed
 * (`documents/42`). A dot is a perfectly legal character in an MQTT topic, so
 * passing `documents.42` through unchanged WORKS — it is a valid one-level
 * topic and messages flow.
 *
 * What it loses is the hierarchy, and with it every wildcard. `documents/+`
 * cannot match a topic with no levels in it, so a subscriber wanting all
 * documents would have to name each one. Since the hierarchy is the whole
 * reason MQTT topics have a separator, the translation is on by default.
 *
 * It is also REVERSIBLE, which constrains it: a channel already containing `/`
 * would translate to a topic indistinguishable from one that had a dot there,
 * so the mapping back would be wrong. Rather than guess,
 * {@see self::toTopic()} refuses such a channel and says why. Setting
 * `MQTT_TOPIC_SEPARATOR=` disables translation entirely and passes channel
 * names through verbatim, which is right for an application whose channels are
 * already MQTT topics.
 */
final class MqttPubSub implements PubSubPort
{
    private bool $running = false;

    /**
     * A {@see self::stop()} that no {@see self::subscribe()} has observed yet.
     *
     * The same sticky flag as {@see MqttClient::$stopRequested}, and for the
     * same reason: a stop can arrive BEFORE the loop is entered — a signal
     * handler firing between the kernel booting and `subscribe()` being called,
     * which under a rolling restart is not rare. With only `$running`,
     * `subscribe()` setting it true would erase the stop and then dial, connect
     * and subscribe to a broker it had already been told to leave alone.
     */
    private bool $stopRequested = false;

    /**
     * Monotonic time until which publishing does not touch the network.
     *
     * See the class docblock. Zero means "not in cooldown".
     */
    private float $silentUntil = 0.0;

    private int $suppressed = 0;

    /** @var \Closure(): float */
    private \Closure $monotonic;

    /** @var \Closure(float): void */
    private \Closure $sleep;

    /**
     * @param \Closure(): float|null     $monotonic see {@see MqttClient}: a wall
     *        clock cannot be used for backoff, because an NTP step would make a
     *        two-second sleep last an hour
     * @param \Closure(float): void|null $sleep     injected so the reconnect
     *        tests do not actually wait
     */
    public function __construct(
        private readonly MqttClient $client,
        private readonly ClientOptions $options,
        private readonly ?LoggerPort $logger = null,
        ?\Closure $monotonic = null,
        ?\Closure $sleep = null,
    ) {
        $this->monotonic = $monotonic ?? static fn (): float => hrtime(true) / 1e9;
        $this->sleep     = $sleep ?? static function (float $seconds): void {
            if ($seconds > 0) {
                usleep((int) ($seconds * 1_000_000));
            }
        };
    }

    public function publish(string $channel, array $payload): int
    {
        try {
            $topic = $this->toTopic($channel);

            if ($topic === null) {
                return -1;
            }

            if (!$this->connectForPublish()) {
                return -1;
            }

            try {
                $this->client->publish($topic, $payload);
            } catch (MqttException $e) {
                if (!$e->connectionLost) {
                    throw $e;
                }

                // One retry, and only for a lost connection. This is the
                // ordinary case after a broker restart: a long-lived worker
                // holds a socket the broker has forgotten, and without the
                // retry the first event after every restart is lost per worker
                // — a once-per-deploy gap that is almost impossible to
                // attribute.
                $this->client->close();

                if (!$this->connectForPublish(force: true)) {
                    return -1;
                }

                $this->client->publish($topic, $payload);
            }

            // 0, not a count. MQTT has no subscriber count at QoS 0 and there
            // is no way to ask. At QoS 1 the broker can say
            // `0x10 No matching subscribers`, which is strictly less
            // information than a count and would still be reported as 0 here —
            // see PubSubPort, where `>= 0` is "accepted" and that is the only
            // thing this backend knows.
            return 0;
        } catch (\Throwable $e) {
            $this->enterCooldown($e);

            return -1;
        }
    }

    public function subscribe(array $channels, callable $onMessage): void
    {
        $filters = [];

        foreach ($channels as $channel) {
            $filter = $this->toFilter($channel);

            // Thrown, where publish() logs. A server told to subscribe to a
            // channel it cannot subscribe to has nothing to do, and starting
            // anyway would hold client connections open and deliver nothing —
            // the exact failure this port's asymmetry exists to prevent.
            Topic::assertFilter($filter);

            $filters[] = $filter;
        }

        if ($filters === []) {
            throw MqttException::invalidFilter('', 'no channels were given to subscribe to');
        }

        // Honour a stop that landed before we got here, BEFORE dialling. See
        // $stopRequested. Returning quietly rather than throwing: nothing went
        // wrong, the loop was simply asked not to start.
        if ($this->stopRequested) {
            $this->stopRequested = false;

            return;
        }

        $this->running = true;
        $attempt       = 0;
        $subscribed    = false;

        while ($this->running) {
            $connectedAt = null;

            try {
                $this->client->connect();
                $this->silentUntil = 0.0;
                $connectedAt       = ($this->monotonic)();

                // Subscribed AFTER connecting, and only ONCE: the client keeps
                // its own subscription table and replays it on every
                // reconnect, so re-adding them here would accumulate a
                // duplicate set per reconnect — and because this client calls
                // every MATCHING subscription's handler, a duplicate is
                // another copy of every message, which looks exactly like the
                // application emitting events twice.
                //
                // Guarded by an explicit flag rather than by `$attempt === 0`,
                // which stopped being equivalent the moment the attempt
                // counter learned to reset itself.
                if (!$subscribed) {
                    $subscribed = true;

                    foreach ($filters as $filter) {
                        $this->client->subscribe(
                            $filter,
                            function (MqttMessage $message) use ($onMessage): void {
                                $payload = $message->json();

                                // A non-JSON or non-object payload is dropped
                                // rather than passed on as something it is not.
                                // For MQTT this is the NORMAL case rather than
                                // an edge: a broker shared with devices carries
                                // protobuf, CBOR and four raw bytes of sensor
                                // float, none of which is a PubSubPort payload.
                                if ($payload === null) {
                                    $this->logger?->debug('mqtt.payload.not_json', [
                                        'topic' => $message->topic,
                                        'bytes' => \strlen($message->payload),
                                    ]);

                                    return;
                                }

                                $onMessage($this->toChannel($message->topic), $payload);
                            },
                            // QoS 0 deliberately. PubSubPort promises
                            // at-most-once and says so; subscribing at QoS 1
                            // would make the broker queue messages for this
                            // client id while it is away, which is a promise
                            // the port cannot keep and the Redis and NATS-core
                            // adapters cannot match.
                            QoS::AtMostOnce,
                        );
                    }
                }

                $this->logger?->info('mqtt.subscribed', [
                    'broker'  => $this->client->describe(),
                    'filters' => $filters,
                ]);

                $this->client->run();

                // run() returned without throwing, which happens only when
                // stop() was called.
                return;
            } catch (MqttException $e) {
                if (!$this->running) {
                    return;
                }

                // MQTT-specific, and the reason this loop is not a copy of the
                // NATS one: some disconnections are made worse by retrying.
                // `0x8E Session taken over` in particular starts a fight with
                // whatever process took the client id.
                $disconnect = $this->client->lastDisconnect();

                if ($disconnect !== null && $disconnect->retryWouldWorsen()) {
                    $this->client->close();

                    throw MqttException::connectionLost(
                        'the MQTT subscription will not be retried: ' . $e->getMessage()
                        . ' Retrying would make this worse rather than better, so the loop is stopping '
                        . 'instead of fighting for the connection.',
                    );
                }

                // A connection that LASTED earns a fresh budget. Resetting on
                // connect SUCCESS instead — which is the obvious thing, and
                // what most clients do — makes the budget unspendable against
                // a broker that accepts a connection and immediately drops it:
                // the counter returns to zero every pass, so the loop retries
                // for ever. A flapping broker is a real state (an OOM-killed
                // node restarting, a half-configured TLS listener), and this is
                // the one that turns it into an infinite hot loop.
                if ($connectedAt !== null && ($this->monotonic)() - $connectedAt >= $this->healthyAfter()) {
                    $attempt = 0;
                }

                ++$attempt;

                if ($this->options->maxReconnects <= 0 || $attempt > $this->options->maxReconnects) {
                    throw MqttException::connectionLost(\sprintf(
                        'the MQTT subscription could not be kept up after %d attempt(s): %s',
                        $attempt,
                        $e->getMessage(),
                    ));
                }

                $wait = $this->backoff($attempt);

                $this->logger?->warning('mqtt.reconnecting', [
                    'attempt' => $attempt,
                    'of'      => $this->options->maxReconnects,
                    'in'      => round($wait, 2),
                    'reason'  => $e->getMessage(),
                ]);

                $this->client->close();
                ($this->sleep)($wait);
            }
        }
    }

    public function stop(): void
    {
        $this->running       = false;
        $this->stopRequested = true;
        $this->client->stop();
    }

    public function describe(): string
    {
        $connAck = $this->client->connAck();

        return 'mqtt ' . $this->client->describe()
            . ($connAck !== null
                ? \sprintf(
                    ' — max QoS %d, receive max %d%s%s',
                    $connAck->maximumQoS()->value,
                    $connAck->receiveMaximum(),
                    $connAck->retainAvailable() ? '' : ', no retain',
                    $connAck->sharedSubscriptionsAvailable() ? '' : ', no shared subscriptions',
                )
                : ' (not yet connected)')
            . ' [no subscriber counts: MQTT does not report them]';
    }

    /** Close the connection. For a CLI command that is finished with it. */
    public function close(): void
    {
        $this->client->close();
    }

    /**
     * The underlying client, for the MQTT features `PubSubPort` has no room for.
     *
     * QoS 1 and 2, retained messages, wills, shared subscriptions and the
     * MQTT 5.0 properties are real capabilities a fan-out port cannot express —
     * `PubSubPort` promises at-most-once to every subscriber, which a shared
     * subscription deliberately breaks and a retained message outlives. They are
     * reached through here rather than through a second connection, because a
     * module that dialled its own would double the connection count per worker,
     * lose this one's reconnect state, and — uniquely to MQTT — need a different
     * client identifier or it would EVICT this one.
     */
    public function client(): MqttClient
    {
        return $this->client;
    }

    // ─── Channel / topic translation ────────────────────────────────────────

    /**
     * A publish topic for $channel, or `null` when it cannot be one.
     *
     * Returns null rather than throwing, because every caller is
     * {@see self::publish()}, which must not throw. The reason is logged.
     */
    private function toTopic(string $channel): ?string
    {
        $trimmed = trim($channel);

        if ($trimmed === '') {
            $this->logger?->warning('mqtt.publish.refused', [
                'channel' => MqttException::printable($channel),
                'reason'  => 'the channel name is empty',
            ]);

            return null;
        }

        $separator = $this->options->topicSeparator;

        if ($separator !== '' && str_contains($trimmed, Topic::SEPARATOR)) {
            // Refused rather than guessed. With translation on, a `/` already
            // in the channel would be indistinguishable in the topic from a
            // translated separator, so mapping the topic back to a channel on
            // the receiving side would produce a different name — and a
            // subscriber would be handed a channel the publisher never used.
            $this->logger?->warning('mqtt.publish.refused', [
                'channel' => MqttException::printable($channel),
                'reason'  => 'it contains "/" while MQTT_TOPIC_SEPARATOR is ['
                    . $separator . '], so the translation to an MQTT topic would not be reversible '
                    . 'and a subscriber would see a different channel name. Either rename the channel '
                    . 'to use [' . $separator . '] as its separator, or set MQTT_TOPIC_SEPARATOR= to '
                    . 'pass channel names through unchanged',
            ]);

            return null;
        }

        $topic = $this->options->topicPrefix
            . ($separator === '' ? $trimmed : str_replace($separator, Topic::SEPARATOR, $trimmed));

        $reason = Topic::reasonNameInvalid($topic);

        if ($reason !== '') {
            // Logged rather than thrown, and the reason is included: a dropped
            // event with "invalid topic" in the log sends somebody to read
            // source, where "it contains a wildcard" does not.
            $this->logger?->warning('mqtt.publish.refused', [
                'channel' => MqttException::printable($channel),
                'topic'   => MqttException::printable($topic),
                'reason'  => $reason,
            ]);

            return null;
        }

        return $topic;
    }

    /**
     * A subscription filter for $channel.
     *
     * `+` and `#` are passed through untranslated: they are MQTT's wildcards
     * and have no dotted equivalent, so an application that wants them writes
     * them literally in the channel name. The translation only touches the
     * separator.
     */
    private function toFilter(string $channel): string
    {
        $trimmed   = trim($channel);
        $separator = $this->options->topicSeparator;

        $filter = $this->options->topicPrefix
            . ($separator === '' ? $trimmed : str_replace($separator, Topic::SEPARATOR, $trimmed));

        if ($this->options->shareName !== '') {
            // A shared subscription makes the broker deliver each message to
            // ONE member of the group. That is queue semantics on a bus, and it
            // is the opposite of what PubSubPort promises — so it is only ever
            // reached when an operator set MQTT_SHARE_NAME deliberately, and
            // `mqtt:status` says so.
            return Topic::shared($this->options->shareName, $filter);
        }

        return $filter;
    }

    /**
     * The channel name a subscriber should see for $topic.
     *
     * The inverse of {@see self::toTopic()}, which is why that method refuses a
     * channel containing `/`.
     */
    private function toChannel(string $topic): string
    {
        $prefix = $this->options->topicPrefix;

        if ($prefix !== '' && str_starts_with($topic, $prefix)) {
            $topic = substr($topic, \strlen($prefix));
        }

        $separator = $this->options->topicSeparator;

        return $separator === '' ? $topic : str_replace(Topic::SEPARATOR, $separator, $topic);
    }

    // ─── Connection management ──────────────────────────────────────────────

    /**
     * Connect if needed, honouring the cooldown.
     *
     * @param bool $force skip the cooldown — used by the one post-restart retry
     */
    private function connectForPublish(bool $force = false): bool
    {
        if ($this->client->isConnected()) {
            return true;
        }

        if (!$force && $this->silentUntil > 0.0 && ($this->monotonic)() < $this->silentUntil) {
            ++$this->suppressed;

            return false;
        }

        try {
            $this->client->connect();
            $this->silentUntil = 0.0;
            $this->suppressed  = 0;

            return true;
        } catch (\Throwable $e) {
            $this->enterCooldown($e);

            return false;
        }
    }

    /**
     * Stop touching the network for a while, and say so exactly once.
     *
     * Logging every suppressed publish would turn a broker outage into a disk
     * full of identical lines, which is its own incident. The count of what was
     * dropped goes on the line that ENDS the cooldown instead, where it is one
     * line that says how bad it was.
     */
    private function enterCooldown(\Throwable $e): void
    {
        $alreadyQuiet = $this->silentUntil > 0.0 && ($this->monotonic)() < $this->silentUntil;

        $this->silentUntil = ($this->monotonic)() + max(0.0, $this->options->failureCooldown);

        if ($alreadyQuiet) {
            return;
        }

        $this->logger?->error('mqtt.publish.failed', [
            'broker'     => $this->client->describe(),
            'reason'     => $e->getMessage(),
            'cooldown'   => $this->options->failureCooldown,
            'suppressed' => $this->suppressed,
            'effect'     => 'events published during the cooldown are dropped without touching the '
                . 'network, so a dead broker costs one timeout rather than one per publish',
        ]);

        $this->suppressed = 0;

        try {
            $this->client->close();
        } catch (\Throwable) {
            // Closing a broken connection must not become the failure.
        }
    }

    /**
     * How long a connection must last to count as healthy.
     *
     * Twice the base backoff: long enough that a connection which dropped
     * before its own first retry interval is treated as a flap, short enough
     * that an ordinary day-long connection obviously qualifies. Floored so a
     * tiny configured `reconnectWait` cannot make every connection "healthy"
     * and restore the infinite loop.
     */
    private function healthyAfter(): float
    {
        return max(1.0, $this->options->reconnectWait * 2);
    }

    /** Exponential, capped, jittered. */
    private function backoff(int $attempt): float
    {
        $base = $this->options->reconnectWait * (2 ** max(0, min($attempt - 1, 6)));

        // Jitter is not decoration. Every worker of a restarted service
        // reconnects at the same instant otherwise, and a synchronised retry
        // storm is how a broker that just came back goes down again.
        return min(60.0, $base) * (0.5 + (random_int(0, 1000) / 1000));
    }
}
