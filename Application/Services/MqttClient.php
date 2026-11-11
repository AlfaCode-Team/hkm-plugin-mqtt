<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Mqtt\API\Contracts\Connection;
use Plugins\Mqtt\Domain\Ack;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\ConnAck;
use Plugins\Mqtt\Domain\Decoder;
use Plugins\Mqtt\Domain\Encoder;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\PacketIds;
use Plugins\Mqtt\Domain\PacketReader;
use Plugins\Mqtt\Domain\PacketType;
use Plugins\Mqtt\Domain\Properties;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\RawPacket;
use Plugins\Mqtt\Domain\ReasonCode;
use Plugins\Mqtt\Domain\ServerDisconnect;
use Plugins\Mqtt\Domain\SubAck;
use Plugins\Mqtt\Domain\Subscription;
use Plugins\Mqtt\Domain\Topic;

/**
 * An MQTT 3.1.1 / 5.0 client: handshake, publish, subscribe, QoS, keepalive.
 *
 * Holds no socket of its own — it drives a {@see Connection}, which is what
 * makes every protocol path above testable without a broker. The transport is
 * one class, in Infrastructure, and it knows nothing about MQTT.
 *
 * THE HANDSHAKE CANNOT SILENTLY SUCCEED, UNLIKE NATS
 * -------------------------------------------------
 * The NATS client in this workspace has to send a PING after CONNECT, because
 * with `verbose: false` a NATS server says nothing for a successful handshake
 * AND nothing before rejecting one — so a wrong password reports success.
 *
 * MQTT has no such hole. CONNACK is mandatory, it is the broker's first packet,
 * and it carries a reason code. A wrong password is `0x86 Bad User Name or
 * Password`, and this client reports it as that.
 *
 * What replaces the problem is subtler and is handled in {@see self::connect()}:
 * a broker that sends NOTHING. That is what a TLS-only listener does when
 * spoken to in plaintext — it reads the CONNECT as a ClientHello, fails, and
 * closes — so the timeout message names that cause, because it is the common
 * one and it looks nothing like itself.
 *
 * SUBSCRIPTIONS ARE STATE, AND SURVIVING A RECONNECT IS THE POINT
 * --------------------------------------------------------------
 * With a clean start the broker forgets every subscription when the connection
 * drops. A client that reconnects but does not re-send its SUBSCRIBE comes back
 * looking entirely healthy — connected, publishing, reading — and receives
 * nothing, for ever.
 *
 * So the subscription table is held here and replayed by
 * {@see self::connect()}. The one case where replaying is WRONG is a resumed
 * session, which the broker signals with `sessionPresent` — there the
 * subscriptions already exist, and re-sending them is merely redundant rather
 * than harmful, so this client replays only what it believes was lost.
 *
 * KEEP-ALIVE IS NOT HOUSEKEEPING HERE
 * -----------------------------------
 * `[MQTT-3.1.2-22]` lets the broker close a connection that has sent nothing
 * for 1.5x the keep-alive. A subscriber on an idle topic sends nothing at all,
 * so without {@see self::pingReq()} on a schedule an idle subscription dies
 * after ninety seconds of quiet and reconnects, repeatedly, which looks like a
 * flapping network.
 *
 * The timer is reset by ANY packet sent, not just a PING — which is why
 * {@see self::send()} is the single write path and updates it.
 */
final class MqttClient
{
    /**
     * One read syscall's worth.
     *
     * 64 KiB rather than 8: a busy topic delivers many small messages, and the
     * cost of reading them is dominated by the number of syscalls, not the
     * bytes. The reader buffers whatever arrives, so a larger chunk never
     * costs correctness — only a slightly larger transient allocation.
     */
    private const READ_CHUNK = 65_536;

    private readonly Encoder $encoder;

    private readonly Decoder $decoder;

    private PacketReader $reader;

    private PacketIds $packetIds;

    /**
     * filter => the subscription and its handler.
     *
     * Keyed by filter, which is also how the broker identifies a subscription:
     * `[MQTT-3.10.4-1]` requires UNSUBSCRIBE to be matched character by
     * character against the filters held, so the filter string IS the identity
     * and a separate local id would be a second name for the same thing.
     *
     * Note the key type is `string` and stays `string` — unlike the NATS
     * client's numeric sids, which PHP silently converts to ints when used as
     * array keys. A filter is never numeric-looking enough to be converted…
     * except that `"123"` is a perfectly legal MQTT topic filter, so the
     * annotation says `int|string` because that is what PHP will actually
     * store, and every read of a key casts back.
     *
     * @var array<int|string, array{subscription: Subscription, handler: callable(MqttMessage): void}>
     */
    private array $subscriptions = [];

    /**
     * Inbound QoS 2 packet identifiers that have been PUBREC'd, awaiting PUBREL.
     *
     * This set is what makes inbound QoS 2 exactly-once. The broker re-sends a
     * PUBLISH it has not seen a PUBREC for, so without remembering which
     * identifiers are already in the exchange, a re-send would be delivered to
     * the application a second time — turning the one QoS level that promises
     * exactly-once into at-least-once with extra round trips.
     *
     * @var array<int, true>
     */
    private array $inboundQos2 = [];

    private bool $running = false;

    /**
     * A {@see self::stop()} that has not yet been observed by a loop.
     *
     * Separate from {@see self::$running} because a stop can arrive BEFORE
     * {@see self::run()} is entered — a signal handler fires between
     * `connect()` and `run()`, which is a window of one TCP handshake plus a
     * round trip and so not rare at all under a rolling restart. With one flag,
     * `run()` setting `running = true` would erase that stop and the process
     * would go on to serve for ever, having been asked to exit.
     */
    private bool $stopRequested = false;

    private bool $handshaken = false;

    private ?ConnAck $connAck = null;

    /** The identifier in use, which the broker may have assigned. */
    private string $effectiveClientId;

    /** The keep-alive actually in force, which the broker may have overridden. */
    private int $effectiveKeepAlive;

    private float $lastSentAt = 0.0;

    private bool $pingOutstanding = false;

    private float $pingSentAt = 0.0;

    /**
     * Acknowledgements collected while pumping, keyed by packet identifier.
     *
     * @var array<int, Ack>
     */
    private array $acks = [];

    /** @var array<int, SubAck> keyed by packet identifier */
    private array $subAcks = [];

    /** Why the broker ended the connection, when it said. */
    private ?ServerDisconnect $lastDisconnect = null;

    /** @var list<string> non-fatal problems, for a status command */
    private array $warnings = [];

    /** @var \Closure(): float */
    private \Closure $monotonic;

    /**
     * @param \Closure(): float|null $monotonic seconds from an arbitrary origin.
     *        NOT {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort}:
     *        that returns whole seconds from the wall clock, and both halves of
     *        that are wrong here. Whole seconds cannot schedule a 0.2-second
     *        read timeout or a sub-second acknowledgement deadline; and a wall
     *        clock steps — an NTP correction or a DST change would make a
     *        backoff sleep for an hour, or a deadline expire instantly.
     *        `hrtime()` is monotonic. Injectable so the tests can drive the
     *        keep-alive schedule and the acknowledgement timeouts without
     *        sleeping.
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly ClientOptions $options,
        private readonly ?LoggerPort $logger = null,
        ?\Closure $monotonic = null,
    ) {
        $this->monotonic          = $monotonic ?? static fn (): float => hrtime(true) / 1e9;
        $this->encoder            = new Encoder($options->version);
        $this->decoder            = new Decoder($options->version);
        $this->reader             = new PacketReader($options->maxPacketBytes);
        $this->packetIds          = new PacketIds();
        $this->effectiveClientId  = $options->clientId->value;
        $this->effectiveKeepAlive = $options->keepAlive;
    }

    /**
     * Dial, CONNECT, read CONNACK, apply the broker's limits, replay subscriptions.
     *
     * @throws MqttException
     */
    public function connect(): ConnAck
    {
        $this->reader->reset();
        $this->handshaken      = false;
        $this->pingOutstanding = false;
        $this->acks            = [];
        $this->subAcks         = [];
        $this->inboundQos2     = [];
        $this->lastDisconnect  = null;

        if ($this->options->cleanStart) {
            // The broker is about to discard its session state, so carrying
            // packet identifiers across would mean waiting for
            // acknowledgements it no longer knows it owes — and worse, a late
            // acknowledgement from the PREVIOUS connection could be matched
            // against a fresh publish that happened to reuse the identifier.
            //
            // Done before the dial rather than after CONNACK because with a
            // clean start the outcome is known in advance; a RESUMED session
            // legitimately keeps its in-flight identifiers, which is why this
            // is conditional rather than unconditional.
            $this->packetIds->reset();
        }

        $this->connection->open();

        $this->send($this->encoder->connect($this->options));

        $connAck = $this->awaitConnAck();

        if (!$connAck->isAccepted()) {
            $this->connection->close();

            throw MqttException::connectRefused(
                $connAck->reasonCode->value,
                $connAck->reasonCode->nameIn(PacketType::ConnAck)
                . ($connAck->reasonCode->remedy() !== '' ? '. ' . $connAck->reasonCode->remedy() : ''),
                $connAck->reasonString() ?? '',
            );
        }

        $this->connAck    = $connAck;
        $this->handshaken = true;

        // ── The broker's limits are not advisory ───────────────────────────
        // Receive Maximum caps unacknowledged QoS 1/2 publishes; exceeding it
        // is 0x93 and a closed connection, so the allocator is told now rather
        // than finding out.
        $this->packetIds->withLimit($connAck->receiveMaximum());

        // [MQTT-3.1.2-21]: when the broker sends a Server Keep Alive "the
        // Client MUST use that value instead". A client that kept its own would
        // ping on the wrong schedule and be timed out while believing itself
        // well inside the window.
        $serverKeepAlive = $connAck->serverKeepAlive();

        if ($serverKeepAlive !== null) {
            $this->effectiveKeepAlive = $serverKeepAlive;

            $this->logger?->info('mqtt.keepalive_overridden', [
                'configured' => $this->options->keepAlive,
                'imposed'    => $serverKeepAlive,
            ]);
        } else {
            $this->effectiveKeepAlive = $this->options->keepAlive;
        }

        $assigned = $connAck->assignedClientId();

        if ($assigned !== null && $assigned !== '') {
            // Only reachable when this client sent an empty id. Recorded so
            // logs and the broker's client list can be lined up at all.
            $this->effectiveClientId = $assigned;
        }

        // [MQTT-3.2.2-4]: a client with NO session state that is told the
        // session is present must close the connection. Honoured because the
        // broker is about to deliver messages for subscriptions this client
        // does not know it has, and acknowledge them against in-flight
        // identifiers it never allocated.
        if ($connAck->sessionPresent && $this->options->cleanStart) {
            $this->connection->close();
            $this->handshaken = false;

            throw MqttException::handshakeFailed(
                'the broker reported Session Present although this client asked for a clean start. '
                . '[MQTT-3.2.2-2] requires Session Present to be 0 when Clean Start is 1, so the broker '
                . 'and this client disagree about whether a session exists — continuing would mean '
                . 'receiving messages for subscriptions this client does not know it has',
            );
        }

        $this->lastSentAt = ($this->monotonic)();

        // ── Replay subscriptions; with a clean start the broker forgot them ──
        if ($this->subscriptions !== [] && !$connAck->sessionPresent) {
            $this->replaySubscriptions();
        }

        return $connAck;
    }

    public function isConnected(): bool
    {
        return $this->handshaken && $this->connection->isOpen();
    }

    public function connAck(): ?ConnAck
    {
        return $this->connAck;
    }

    /** The identifier in force, which the broker may have assigned. */
    public function clientId(): string
    {
        return $this->effectiveClientId;
    }

    public function keepAlive(): int
    {
        return $this->effectiveKeepAlive;
    }

    /**
     * Publish a message.
     *
     * WHAT RETURNING MEANS, PER QoS. At QoS 0 it means the bytes were handed to
     * the socket and nothing more — there is no acknowledgement, so a broker
     * that refuses the topic says so by closing the connection or not at all.
     * At QoS 1 and 2 it means the broker ACKNOWLEDGED the message, and the
     * returned {@see Ack} carries its reason code — including
     * `0x10 No matching subscribers`, which is a success that means the message
     * was discarded.
     *
     * The QoS 0 case is why this drains anything already waiting first, with a
     * zero-length wait. A publish-only process — anything under PHP-FPM —
     * never reads, so a DISCONNECT the broker sent would never be seen, and the
     * process would write into a dead socket for every subsequent request. The
     * realistic cause is `0x8E Session taken over`: another process took this
     * client id. One non-blocking read per publish surfaces it.
     *
     * @param  array<string, mixed>|string $payload an array is JSON-encoded
     * @return ?Ack `null` at QoS 0; the acknowledgement at QoS 1 and 2
     * @throws MqttException on an invalid topic, a lost connection, an
     *         exhausted identifier space, or a timeout waiting for the
     *         acknowledgement
     */
    public function publish(
        string $topic,
        array|string $payload,
        ?QoS $qos = null,
        ?bool $retain = null,
        ?Properties $properties = null,
        ?float $timeout = null,
    ): ?Ack {
        if (!$this->isConnected()) {
            throw MqttException::notConnected('publish');
        }

        $qos ??= $this->options->defaultQos;
        $retain ??= $this->options->defaultRetain;

        // The broker's own limits are checked FIRST, before the socket is
        // touched at all. A publish this client already knows the broker will
        // refuse should not cost a read, and checking first makes "nothing was
        // written" true without qualification.
        $this->assertBrokerAllows($qos, $retain);

        $this->drainAvailable();

        $bytes = \is_string($payload) ? $payload : self::encode($payload);

        if ($qos === QoS::AtMostOnce) {
            $this->send($this->encoder->publish($topic, $bytes, $qos, $retain, null, $properties));

            return null;
        }

        $packetId = $this->packetIds->allocate();

        try {
            $this->send($this->encoder->publish($topic, $bytes, $qos, $retain, $packetId, $properties));

            $expected = $qos === QoS::AtLeastOnce ? PacketType::PubAck : PacketType::PubRec;
            $ack      = $this->awaitAck($packetId, $expected, $timeout);

            if ($qos === QoS::AtLeastOnce) {
                return $ack;
            }

            // QoS 2, second half. A PUBREC with a reason code of 128 or above
            // ENDS the exchange — the broker is refusing the message, and
            // sending PUBREL would be continuing an exchange that has already
            // failed.
            if ($ack->isError()) {
                return $ack;
            }

            $this->send($this->encoder->ack(PacketType::PubRel, $packetId));

            return $this->awaitAck($packetId, PacketType::PubComp, $timeout);
        } finally {
            // Released whatever happened. On a timeout the identifier would
            // otherwise stay in flight for the life of the connection, and
            // enough timeouts would exhaust the space and refuse every
            // subsequent QoS 1 publish.
            $this->packetIds->release($packetId);
        }
    }

    /**
     * Subscribe to $filter and wait for the SUBACK.
     *
     * The round trip is deliberate. A SUBSCRIBE that the broker refuses —
     * `0x87 Not authorized` on a topic the credentials cannot read,
     * `0x8F Topic Filter invalid` for a broker-specific restriction — is
     * answered with a SUBACK and nothing else. A client that did not wait would
     * report a successful subscription, receive nothing, and look exactly like
     * a system in which nothing is being published. Subscribing is rare; the
     * round trip is cheap.
     *
     * The handler runs inside {@see self::run()}. It must not throw for
     * ordinary bad input: an exception unwinds the read loop, which is the
     * subscriber's main loop, so one malformed message from an unrelated
     * publisher on a shared broker would stop the process.
     *
     * @param  callable(MqttMessage): void $handler
     * @throws MqttException when the filter is unusable or the broker refuses it
     */
    public function subscribe(
        string $filter,
        callable $handler,
        ?QoS $qos = null,
        bool $noLocal = false,
        ?float $timeout = null,
    ): SubAck {
        $subscription = new Subscription(
            filter: $filter,
            qos: $qos ?? $this->options->defaultQos,
            noLocal: $noLocal,
        );

        return $this->subscribeWith([$subscription], [$handler], $timeout);
    }

    /**
     * Subscribe to several filters in one SUBSCRIBE.
     *
     * One packet and one round trip for the lot, which matters for a subscriber
     * with twenty topics — and the broker answers with one reason code per
     * filter, in order, which is why the handlers are a parallel list.
     *
     * @param  non-empty-list<Subscription>          $subscriptions
     * @param  list<callable(MqttMessage): void>     $handlers parallel to $subscriptions
     * @throws MqttException when a filter is unusable, when the lists disagree
     *         in length, or when the broker refuses any filter
     */
    public function subscribeWith(array $subscriptions, array $handlers, ?float $timeout = null): SubAck
    {
        if (\count($subscriptions) !== \count($handlers)) {
            throw MqttException::cannotEncode(
                'there are ' . \count($subscriptions) . ' subscription(s) and ' . \count($handlers)
                . ' handler(s). They are paired by position — the SUBACK names no filters, only an '
                . 'ordered list of reason codes — so a mismatch would attach results to the wrong '
                . 'topics',
            );
        }

        if (!$this->isConnected()) {
            throw MqttException::notConnected('subscribe');
        }

        $this->assertBrokerAllowsFilters($subscriptions);

        $packetId = $this->packetIds->allocate();
        $filters  = array_map(static fn (Subscription $s): string => $s->filter, $subscriptions);

        // Encoded FIRST, so an invalid filter cannot leave a recorded entry
        // that a later reconnect would faithfully replay. Nothing is written or
        // recorded if this throws.
        $packet = $this->encoder->subscribe($packetId, $subscriptions);

        // ── RECORDED BEFORE THE SUBSCRIBE GOES OUT ─────────────────────────
        // Not tidiness — correctness, and the bug it fixes is invisible without
        // a real broker. A retained message is sent by the broker IMMEDIATELY
        // after the SUBACK, and the two routinely arrive in the SAME TCP
        // segment. So `awaitSubAck()` reads both at once, dispatches the
        // PUBLISH, and if the subscription were not yet recorded the message
        // would find no handler and be dropped.
        //
        // Since retained messages always arrive at exactly that moment, the
        // effect was that this client lost essentially every retained message —
        // while reporting a successful subscription. Recording first closes the
        // window; a refusal below removes the entry again.
        $provisional = [];

        foreach ($subscriptions as $index => $subscription) {
            $provisional[$subscription->filter] = isset($this->subscriptions[$subscription->filter]);

            $this->subscriptions[$subscription->filter] = [
                'subscription' => $subscription,
                'handler'      => $handlers[$index],
            ];
        }

        try {
            $this->send($packet);

            $subAck = $this->awaitSubAck($packetId, $filters, $timeout);
        } catch (\Throwable $e) {
            // The SUBSCRIBE failed or timed out, so the broker may never have
            // registered it. Entries this call added are removed; one that
            // already existed is left alone, because it belongs to an earlier
            // successful subscribe.
            foreach ($provisional as $filter => $existedBefore) {
                if (!$existedBefore) {
                    unset($this->subscriptions[$filter]);
                }
            }

            throw $e;
        } finally {
            $this->packetIds->release($packetId);
        }

        $refusals = $subAck->refusals();

        if ($refusals !== []) {
            // Remove the provisional entries for the filters the broker
            // refused. Only those: the rest were granted and must stay, so a
            // partially refused batch leaves exactly the subscriptions that
            // exist on the broker and no others.
            foreach ($refusals as $refusal) {
                if (($provisional[$refusal['filter']] ?? true) === false) {
                    unset($this->subscriptions[$refusal['filter']]);
                }
            }

            $detail = implode('; ', array_map(
                static fn (array $r): string => '[' . $r['filter'] . '] ' . $r['code']
                    . ($r['remedy'] !== '' ? ' — ' . $r['remedy'] : ''),
                $refusals,
            ));

            throw MqttException::subscribeRefused($detail);
        }

        foreach ($subscriptions as $index => $subscription) {
            $granted = $subAck->grantedQoS($index);

            if ($granted !== null && $granted->value < $subscription->qos->value) {
                // A lower granted QoS is a success, and it is worth saying out
                // loud: a subscriber that asked for QoS 2 and was granted QoS 0
                // has no exactly-once guarantee and no error to tell it so.
                $this->warnings[] = 'the broker granted ' . $granted->label() . ' on ['
                    . $subscription->filter . '] where ' . $subscription->qos->label()
                    . ' was requested';

                $this->logger?->warning('mqtt.qos_downgraded', [
                    'filter'  => $subscription->filter,
                    'asked'   => $subscription->qos->value,
                    'granted' => $granted->value,
                ]);
            }

            $this->subscriptions[$subscription->filter] = [
                'subscription' => $granted !== null && $granted->value < $subscription->qos->value
                    ? new Subscription(
                        filter: $subscription->filter,
                        qos: $granted,
                        noLocal: $subscription->noLocal,
                        retainAsPublished: $subscription->retainAsPublished,
                        retainHandling: $subscription->retainHandling,
                        subscriptionIdentifier: $subscription->subscriptionIdentifier,
                    )
                    : $subscription,
                'handler' => $handlers[$index],
            ];
        }

        return $subAck;
    }

    /**
     * Unsubscribe from $filters.
     *
     * The filters must be spelled EXACTLY as they were subscribed:
     * `[MQTT-3.10.4-1]` requires the broker to compare them character by
     * character, so a filter that differs by a trailing `/` or a case is simply
     * not found — and the UNSUBACK reports `0x11 No subscription existed`,
     * which is a success. A caller that ignored it would believe it had
     * unsubscribed and keep receiving messages.
     *
     * @param  non-empty-list<string> $filters
     * @throws MqttException
     */
    public function unsubscribe(array $filters, ?float $timeout = null): SubAck
    {
        if (!$this->isConnected()) {
            throw MqttException::notConnected('unsubscribe');
        }

        $packetId = $this->packetIds->allocate();

        try {
            $this->send($this->encoder->unsubscribe($packetId, $filters));

            $unsubAck = $this->awaitSubAck($packetId, $filters, $timeout);
        } finally {
            $this->packetIds->release($packetId);
        }

        foreach ($filters as $index => $filter) {
            $code = $unsubAck->reasonCodes[$index] ?? null;

            if ($code === ReasonCode::NoSubscriptionExisted) {
                $this->warnings[] = 'unsubscribing from [' . $filter . '] matched no subscription on '
                    . 'the broker; filters are compared character by character, so this is usually a '
                    . 'filter spelled differently from the one subscribed';
            }

            unset($this->subscriptions[$filter]);
        }

        return $unsubAck;
    }

    /**
     * Read and dispatch until {@see self::stop()}, or for $seconds.
     *
     * @param  float $seconds 0 means until stopped — the server case
     * @throws MqttException when the connection dies, when the broker sends a
     *         DISCONNECT, or when the keepalive goes unanswered. Never returns
     *         quietly on a broken link: a subscriber that stopped listening
     *         without saying so is indistinguishable from a system where
     *         nothing is happening, which is the failure that takes longest to
     *         find
     */
    public function run(float $seconds = 0.0): void
    {
        if (!$this->isConnected()) {
            throw MqttException::notConnected('run a subscriber loop');
        }

        // Honour a stop that landed before we got here. See $stopRequested.
        if ($this->stopRequested) {
            $this->stopRequested = false;

            return;
        }

        $this->running = true;
        $deadline      = $seconds > 0 ? ($this->monotonic)() + $seconds : 0.0;

        while ($this->running) {
            $wait = $this->options->readTimeout;

            if ($deadline > 0.0) {
                $remaining = $deadline - ($this->monotonic)();

                if ($remaining <= 0) {
                    return;
                }

                $wait = min($wait, $remaining);
            }

            $this->pump($wait);
        }
    }

    /**
     * Ask {@see self::run()} to return.
     *
     * Safe from a signal handler or another coroutine: it sets a flag, and the
     * loop notices at its next read timeout. So shutdown latency is bounded by
     * `readTimeout` — which is why that default is seconds rather than minutes,
     * even though the protocol would be happy with minutes.
     */
    public function stop(): void
    {
        $this->running       = false;
        $this->stopRequested = true;
    }

    /**
     * Send DISCONNECT and close.
     *
     * The reason code matters more than it looks. A plain DISCONNECT tells the
     * broker this was a clean exit, and the broker then DISCARDS the will — so
     * a process with a "down" will that shuts down politely publishes no
     * "down", and everything watching its status topic still believes it is up.
     *
     * `$withWill` sends `0x04 Disconnect with Will Message` instead, which is
     * how to exit cleanly AND have the will fire. It is MQTT 5.0 only; on 3.1.1
     * a DISCONNECT always discards the will and there is no way to ask
     * otherwise.
     */
    public function disconnect(bool $withWill = false): void
    {
        if ($this->isConnected()) {
            try {
                $this->send($this->encoder->disconnect(
                    $withWill && $this->options->version->hasProperties()
                        ? ReasonCode::DisconnectWithWillMessage
                        : ReasonCode::Success,
                ));
            } catch (MqttException) {
                // A DISCONNECT is a courtesy. If the socket has already gone
                // there is nothing to report and nothing to do differently —
                // the broker will fire the will, which is the correct outcome
                // for a connection that died.
            }
        }

        $this->close();
    }

    public function close(): void
    {
        $this->running    = false;
        $this->handshaken = false;
        $this->connection->close();
        $this->reader->reset();
    }

    /**
     * Non-fatal problems seen on this connection, for a status command.
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /** Why the broker ended the connection, when it said (MQTT 5.0 only). */
    public function lastDisconnect(): ?ServerDisconnect
    {
        return $this->lastDisconnect;
    }

    /** @return list<string> the filters currently subscribed */
    public function subscribedFilters(): array
    {
        return array_map('strval', array_keys($this->subscriptions));
    }

    public function inFlightCount(): int
    {
        return $this->packetIds->inFlightCount();
    }

    public function describe(): string
    {
        return $this->connection->describe()
            . ($this->connection->isEncrypted() ? ' (TLS)' : ' (plaintext)')
            . ', ' . $this->options->version->label()
            . ', client id ' . ($this->effectiveClientId === '' ? '(broker-assigned)' : $this->effectiveClientId)
            . ($this->options->user !== '' ? ', authenticated' : ', no credentials');
    }

    // ─── Internals ──────────────────────────────────────────────────────────

    /**
     * The single write path, which is also the keep-alive timer.
     *
     * Every packet goes through here so {@see self::$lastSentAt} cannot drift
     * out of step with what was actually sent. The timer must be reset by ANY
     * packet, not just a PING: a client publishing steadily never needs to
     * ping at all, and one that pinged on a fixed schedule regardless would
     * send pointless packets forever.
     *
     * @throws MqttException
     */
    private function send(string $packet): void
    {
        $this->connection->write($packet);
        $this->lastSentAt = ($this->monotonic)();
    }

    /**
     * One read-and-dispatch cycle, plus the keepalive.
     *
     * @throws MqttException
     */
    private function pump(float $wait): void
    {
        $bytes = $this->connection->read(self::READ_CHUNK, max(0.0, $wait));

        if ($bytes !== '') {
            $this->reader->append($bytes);
            $this->drain();
        }

        $this->sendKeepaliveIfDue();
    }

    /**
     * Process anything already buffered or instantly available, without waiting.
     *
     * Used by {@see self::publish()} so a publish-only process still notices a
     * DISCONNECT or a closed connection. See that method for why.
     *
     * @throws MqttException
     */
    private function drainAvailable(): void
    {
        $bytes = $this->connection->read(self::READ_CHUNK, 0.0);

        if ($bytes !== '') {
            $this->reader->append($bytes);
        }

        $this->drain();
    }

    /**
     * Turn buffered bytes into dispatched packets.
     *
     * @throws MqttException
     */
    private function drain(): void
    {
        while (($packet = $this->reader->next()) !== null) {
            $this->handle($packet);
        }
    }

    /** @throws MqttException */
    private function handle(RawPacket $packet): void
    {
        switch ($packet->type) {
            case PacketType::Publish:
                $this->deliver($this->decoder->publish($packet));
                break;

            case PacketType::PubAck:
            case PacketType::PubComp:
                $ack = $this->decoder->ack($packet);
                $this->acks[$ack->packetId] = $ack;
                break;

            case PacketType::PubRec:
                $ack = $this->decoder->ack($packet);
                $this->acks[$ack->packetId] = $ack;
                break;

            case PacketType::PubRel:
                // The third packet of an INBOUND QoS 2 exchange. The broker is
                // confirming it will not re-send, so the identifier can be
                // forgotten and PUBCOMP ends the exchange.
                $ack = $this->decoder->ack($packet);
                unset($this->inboundQos2[$ack->packetId]);
                $this->send($this->encoder->ack(PacketType::PubComp, $ack->packetId));
                break;

            case PacketType::SubAck:
            case PacketType::UnsubAck:
                // Decoded without the filter list, so the count check is
                // skipped here and applied by awaitSubAck(), which knows what
                // was asked for.
                $subAck = $this->decoder->subAck($packet);
                $this->subAcks[$subAck->packetId] = $subAck;
                break;

            case PacketType::PingResp:
                $this->decoder->pingResp($packet);
                $this->pingOutstanding = false;
                break;

            case PacketType::Disconnect:
                $this->handleServerDisconnect($this->decoder->disconnect($packet));
                break;

            case PacketType::ConnAck:
                // A second CONNACK. Unlike NATS, where a repeated INFO is
                // routine during a rolling restart, MQTT sends exactly one
                // CONNACK per connection — so this means the peer has lost the
                // plot, and continuing would mean acting on limits for a
                // session that is not this one.
                throw MqttException::malformedPacket(
                    'a second CONNACK arrived on an established connection; a broker sends exactly one '
                    . 'per connection',
                );

            case PacketType::Connect:
            case PacketType::Subscribe:
            case PacketType::Unsubscribe:
            case PacketType::PingReq:
                throw MqttException::malformedPacket(
                    $packet->type->label() . ' arrived from the broker, and it is a packet only a '
                    . 'CLIENT sends — so the peer is either broken or is not a broker',
                );

            case PacketType::Auth:
                // Enhanced authentication (AUTH / SASL-style exchanges) is not
                // implemented. Refused rather than ignored: the broker is
                // waiting for a reply this client will never send, so the
                // handshake would hang until the timeout and report nothing
                // useful.
                throw MqttException::handshakeFailed(
                    'the broker sent AUTH, which begins MQTT 5.0 enhanced authentication. This client '
                    . 'implements user name and password authentication only, so there is no reply it '
                    . 'can make and the broker would wait indefinitely. Configure the broker for '
                    . 'password authentication, or clear any Authentication Method property',
                );
        }
    }

    /** @throws MqttException */
    private function handleServerDisconnect(ServerDisconnect $disconnect): void
    {
        $this->lastDisconnect = $disconnect;
        $this->handshaken     = false;
        $this->running        = false;

        $this->logger?->error('mqtt.server_disconnect', [
            'reason'   => $disconnect->describe(),
            'detail'   => $disconnect->reasonString(),
            'broker'   => $this->connection->describe(),
            'clientId' => $this->effectiveClientId,
        ]);

        throw MqttException::serverDisconnected(
            $disconnect->reasonCode->value,
            $disconnect->reasonCode->nameIn(PacketType::Disconnect)
            . ($disconnect->reasonCode->remedy() !== '' ? '. ' . $disconnect->reasonCode->remedy() : ''),
            $disconnect->reasonString() ?? '',
        );
    }

    /**
     * Acknowledge an inbound message and route it to every matching handler.
     *
     * ROUTING IS BY MATCHING, NOT BY IDENTIFIER. A PUBLISH carries the concrete
     * topic, never the filter that caused delivery — so a client subscribed to
     * `sensors/+/temp` receiving `sensors/3/temp` has to work out for itself
     * which handler to call. That is what {@see Topic::matches()} is for, and it
     * has to agree with the broker exactly.
     *
     * A message matching TWO subscriptions calls BOTH handlers. That mirrors
     * the protocol — two subscriptions are two reasons to be told — and the
     * alternative, picking one, would make which handler runs depend on
     * iteration order.
     *
     * @throws MqttException
     */
    private function deliver(MqttMessage $message): void
    {
        // ── Acknowledge FIRST, before the handler runs ─────────────────────
        // At QoS 1 that is a deliberate choice between two imperfect orders.
        // Acknowledging first risks losing a message if the handler then
        // throws; acknowledging after risks the broker re-sending because the
        // handler was slow. The first is chosen because the handler is
        // application code that may block indefinitely, and a PUBACK withheld
        // that long means the broker re-delivers while the first copy is still
        // being processed — turning one slow message into an unbounded stream
        // of duplicates. At-least-once already requires an idempotent handler,
        // so this order costs nothing the contract did not already demand.
        if ($message->qos === QoS::AtLeastOnce && $message->packetId !== null) {
            $this->send($this->encoder->ack(PacketType::PubAck, $message->packetId));
        }

        if ($message->qos === QoS::ExactlyOnce && $message->packetId !== null) {
            $alreadySeen = isset($this->inboundQos2[$message->packetId]);

            // PUBREC either way: the broker re-sent precisely because it did
            // not see the first one, so staying silent would leave it
            // re-sending for ever.
            $this->send($this->encoder->ack(PacketType::PubRec, $message->packetId));

            if ($alreadySeen) {
                // This is the one place exactly-once is actually delivered. The
                // identifier is mid-exchange, so this PUBLISH is a re-send of
                // one already given to the application — and handing it over
                // again would make QoS 2 behave as QoS 1 with extra packets.
                return;
            }

            $this->inboundQos2[$message->packetId] = true;
        }

        $delivered = 0;

        foreach ($this->subscriptions as $entry) {
            if (!$entry['subscription']->matches($message->topic)) {
                continue;
            }

            ++$delivered;
            ($entry['handler'])($message);
        }

        if ($delivered === 0) {
            // Not an error, and not silent either. It happens legitimately
            // while an UNSUBSCRIBE and an in-flight delivery race. It also
            // happens when this client's matcher disagrees with the broker's,
            // which would be a bug here — and the only symptom would be
            // messages arriving and nothing happening.
            $this->logger?->warning('mqtt.unmatched_message', [
                'topic'   => $message->topic,
                'filters' => $this->subscribedFilters(),
            ]);
        }
    }

    /**
     * Send a PINGREQ when one is due, and declare the link dead when unanswered.
     *
     * The broker's own timeout only proves WE are alive to IT. A half-open
     * connection — a NAT that silently dropped the flow, a host that slept, a
     * middlebox idle timeout — delivers nothing and reports nothing, and the
     * only way to find out is to ask and notice that no answer came.
     *
     * Named `sendKeepaliveIfDue` rather than `keepalive` because PHP method
     * names are case-insensitive, so a private `keepalive()` beside the public
     * {@see self::keepAlive()} accessor is a redeclaration and a fatal error.
     *
     * @throws MqttException
     */
    private function sendKeepaliveIfDue(): void
    {
        // 80% of the keep-alive, floored at half a second.
        //
        // The floor is 0.5 and not 1.0, and that is a bug fix rather than a
        // tuning choice: with a keep-alive of 1 second a floor of 1.0 makes the
        // interval the WHOLE window, so the first ping is due exactly when the
        // broker's patience begins to run out and in practice arrives after it
        // has closed the socket. Measured against a real broker, which dropped
        // every keep-alive-1 connection before a PINGREQ ever went out.
        //
        // The margin is the entire point of using 80% rather than 100%: the
        // packet has to travel, and the broker's deadline is 1.5x.
        $interval = $this->effectiveKeepAlive <= 0
            ? 0.0
            : max(0.5, $this->effectiveKeepAlive * 0.8);

        if ($interval <= 0.0) {
            // A keep-alive of zero disables the mechanism. Legal, and it means
            // the broker will never time this connection out — so a half-open
            // socket is never noticed by either end.
            return;
        }

        $now = ($this->monotonic)();

        if ($this->pingOutstanding) {
            // The broker's patience is 1.5x the keep-alive, so waiting longer
            // than that would mean still hoping after it had already closed
            // the socket.
            $limit = max(1.0, $this->effectiveKeepAlive * 1.5);

            if ($now - $this->pingSentAt >= $limit) {
                $this->handshaken = false;

                throw MqttException::connectionLost(\sprintf(
                    'a PINGREQ went unanswered for %.0fs, which is past the %.0fs the broker itself '
                    . 'would have waited, so this link is half-open — it would otherwise look exactly '
                    . 'like an idle topic',
                    $now - $this->pingSentAt,
                    $limit,
                ));
            }

            return;
        }

        // Measured from the last packet SENT, not the last ping: a client
        // publishing steadily satisfies the keep-alive without pinging at all.
        if ($now - $this->lastSentAt < $interval) {
            return;
        }

        $this->send($this->encoder->pingReq());
        $this->pingOutstanding = true;
        $this->pingSentAt      = $now;
    }

    /**
     * Read until CONNACK.
     *
     * @throws MqttException
     */
    private function awaitConnAck(): ConnAck
    {
        $deadline = ($this->monotonic)() + $this->options->connectTimeout;

        while (true) {
            $packet = $this->reader->next();

            if ($packet !== null) {
                // [MQTT-3.2.0-1] makes CONNACK the broker's first packet, so
                // anything else here means the peer is not an MQTT broker, or
                // not following the protocol.
                return $this->decoder->connAck($packet);
            }

            $remaining = $deadline - ($this->monotonic)();

            if ($remaining <= 0) {
                throw MqttException::handshakeFailed(\sprintf(
                    'no CONNACK within %.1fs. CONNACK is mandatory and is the broker\'s first packet, '
                    . 'so silence means the bytes never reached a broker: the commonest cause is a '
                    . 'TLS-only listener spoken to in plaintext, which reads the CONNECT as a '
                    . 'ClientHello and closes without answering%s',
                    $this->options->connectTimeout,
                    $this->connection->isEncrypted()
                        ? ' (this connection IS encrypted, so that is not the cause here)'
                        : ' — try mqtts:// or port 8883',
                ));
            }

            $this->reader->append($this->connection->read(self::READ_CHUNK, $remaining));
        }
    }

    /**
     * Read until the acknowledgement for $packetId arrives.
     *
     * Messages that arrive in the meantime are dispatched rather than dropped:
     * this is called on a live connection with subscriptions, and discarding
     * whatever was in flight would lose it silently.
     *
     * @throws MqttException on timeout or a wrong packet type
     */
    private function awaitAck(int $packetId, PacketType $expected, ?float $timeout): Ack
    {
        $limit    = $timeout ?? $this->options->readTimeout;
        $deadline = ($this->monotonic)() + max(0.001, $limit);

        while (true) {
            if (isset($this->acks[$packetId])) {
                $ack = $this->acks[$packetId];
                unset($this->acks[$packetId]);

                if ($ack->type !== $expected) {
                    throw MqttException::malformedPacket(
                        'expected ' . $expected->label() . ' for packet identifier ' . $packetId
                        . ' and got ' . $ack->type->label()
                        . '. The QoS exchange is a fixed sequence, so a packet out of order means the '
                        . 'broker and this client disagree about which step they are on',
                    );
                }

                return $ack;
            }

            $remaining = $deadline - ($this->monotonic)();

            if ($remaining <= 0) {
                throw MqttException::timedOut(
                    $expected->label() . ' for packet identifier ' . $packetId,
                    $limit,
                );
            }

            $this->pump(min($remaining, $this->options->readTimeout));
        }
    }

    /**
     * Read until the SUBACK or UNSUBACK for $packetId arrives.
     *
     * @param  list<string> $filters what was asked for, so the reason codes can
     *         be attributed and a count mismatch detected
     * @throws MqttException on timeout, or when the reply does not line up
     */
    private function awaitSubAck(int $packetId, array $filters, ?float $timeout): SubAck
    {
        $limit    = $timeout ?? $this->options->readTimeout;
        $deadline = ($this->monotonic)() + max(0.001, $limit);

        while (true) {
            if (isset($this->subAcks[$packetId])) {
                $subAck = $this->subAcks[$packetId];
                unset($this->subAcks[$packetId]);

                // An MQTT 3.1.1 UNSUBACK has no payload at all — the packet
                // identifier IS the acknowledgement. Synthesise one Success per
                // filter so a caller sees the same shape on both versions and
                // `isFullyGranted()` means something; 3.1.1 simply offers no
                // per-filter detail to report.
                if (
                    $subAck->reasonCodes === []
                    && $subAck->type === PacketType::UnsubAck
                    && !$this->options->version->hasProperties()
                ) {
                    return new SubAck(
                        $subAck->type,
                        $subAck->packetId,
                        array_fill(0, \count($filters), ReasonCode::Success),
                        $subAck->properties,
                        $filters,
                    );
                }

                if (\count($subAck->reasonCodes) !== \count($filters)) {
                    throw MqttException::malformedPacket(
                        'the ' . $subAck->type->label() . ' carried ' . \count($subAck->reasonCodes)
                        . ' reason code(s) for ' . \count($filters) . ' requested filter(s). The reply '
                        . 'names no filters — position is the only thing pairing them — so a mismatch '
                        . 'makes every result unattributable, and treating any filter as subscribed '
                        . 'would be a guess',
                    );
                }

                // Re-made with the filters attached, so refusals can name the
                // topic that caused them.
                return new SubAck(
                    $subAck->type,
                    $subAck->packetId,
                    $subAck->reasonCodes,
                    $subAck->properties,
                    $filters,
                );
            }

            $remaining = $deadline - ($this->monotonic)();

            if ($remaining <= 0) {
                throw MqttException::timedOut(
                    'a SUBACK/UNSUBACK for packet identifier ' . $packetId,
                    $limit,
                );
            }

            $this->pump(min($remaining, $this->options->readTimeout));
        }
    }

    /** @throws MqttException */
    private function replaySubscriptions(): void
    {
        $subscriptions = [];

        // Only the subscriptions are needed, not the handlers: the handlers are
        // already in $this->subscriptions and are untouched by a reconnect.
        // Re-collecting them here would imply this method re-registers them,
        // which it must not — overwriting an entry would lose a QoS the broker
        // had downgraded on the previous connection.
        foreach ($this->subscriptions as $entry) {
            $subscriptions[] = $entry['subscription'];
        }

        if ($subscriptions === []) {
            return;
        }

        $packetId = $this->packetIds->allocate();
        $filters  = array_map(static fn (Subscription $s): string => $s->filter, $subscriptions);

        try {
            $this->send($this->encoder->subscribe($packetId, $subscriptions));

            $subAck = $this->awaitSubAck($packetId, $filters, $this->options->connectTimeout);
        } finally {
            $this->packetIds->release($packetId);
        }

        $refusals = $subAck->refusals();

        if ($refusals !== []) {
            // A replay that is refused is worse than a failed subscribe,
            // because the application already believes it is subscribed. It
            // must not be swallowed: the process would come back connected,
            // healthy and deaf.
            throw MqttException::subscribeRefused(
                'on reconnect, the broker refused ' . \count($refusals) . ' of ' . \count($filters)
                . ' subscription(s) it had previously granted: '
                . implode('; ', array_map(
                    static fn (array $r): string => '[' . $r['filter'] . '] ' . $r['code'],
                    $refusals,
                )),
            );
        }

        $this->logger?->info('mqtt.resubscribed', [
            'count'  => \count($filters),
            'broker' => $this->connection->describe(),
        ]);
    }

    /**
     * Refuse what the broker said in CONNACK that it will not do.
     *
     * Checked locally because the broker's remedy is to close the connection
     * (`0x9B QoS not supported`, `0x9A Retain not supported`), which costs every
     * subscription on the link rather than just this publish.
     *
     * @throws MqttException
     */
    private function assertBrokerAllows(QoS $qos, bool $retain): void
    {
        $connAck = $this->connAck;

        if ($connAck === null) {
            return;
        }

        if ($qos->value > $connAck->maximumQoS()->value) {
            throw MqttException::cannotEncode(
                'this publish asks for ' . $qos->label() . ', but the broker advertised a Maximum QoS '
                . 'of ' . $connAck->maximumQoS()->value . ' in its CONNACK. Sending it anyway earns '
                . '0x9B QoS not supported, which closes the connection and takes every subscription on '
                . 'it. Lower MQTT_QOS',
            );
        }

        if ($retain && !$connAck->retainAvailable()) {
            throw MqttException::cannotEncode(
                'this publish asks for the message to be retained, but the broker advertised that '
                . 'retained messages are not available. Sending it anyway earns 0x9A Retain not '
                . 'supported, which closes the connection',
            );
        }
    }

    /**
     * Refuse filters the broker said it does not support.
     *
     * @param  list<Subscription> $subscriptions
     * @throws MqttException
     */
    private function assertBrokerAllowsFilters(array $subscriptions): void
    {
        $connAck = $this->connAck;

        if ($connAck === null) {
            return;
        }

        foreach ($subscriptions as $subscription) {
            $filter = $subscription->filter;

            if (
                !$connAck->wildcardSubscriptionsAvailable()
                && (str_contains($filter, Topic::MULTI_WILDCARD) || str_contains($filter, Topic::SINGLE_WILDCARD))
            ) {
                throw MqttException::cannotEncode(
                    'the filter [' . $filter . '] uses a wildcard, but the broker advertised that '
                    . 'wildcard subscriptions are not available. Every topic must be named explicitly '
                    . 'on this broker',
                );
            }

            if (!$connAck->sharedSubscriptionsAvailable() && Topic::isShared($filter)) {
                throw MqttException::cannotEncode(
                    'the filter [' . $filter . '] is a shared subscription, but the broker advertised '
                    . 'that shared subscriptions are not available. Without them every subscriber '
                    . 'receives every message, so a work queue needs a real queue rather than a bus',
                );
            }
        }
    }

    /**
     * JSON for the wire.
     *
     * @param  array<string, mixed> $payload
     * @throws MqttException on data that cannot be encoded, rather than
     *         publishing the string "false"
     */
    private static function encode(array $payload): string
    {
        try {
            return json_encode($payload, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $e) {
            throw MqttException::cannotEncode(
                'the payload could not be encoded as JSON: ' . $e->getMessage(),
            );
        }
    }
}
