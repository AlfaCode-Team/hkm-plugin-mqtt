<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Infrastructure\Adapters\MqttPubSub;

/**
 * The `PubSubPort` adapter — whose two halves pull in opposite directions.
 *
 * `publish()` must not throw, because it is called after the work it announces
 * has already been committed. `subscribe()` must throw, because it IS the
 * server's main loop and a subscriber that quietly stopped listening is
 * indistinguishable from a system where nothing is happening.
 */
final class PubSubAdapterTest extends TestCase
{
    /**
     * THE CONTRACT. `publish()` is called from inside a request to announce
     * something already committed — the row is written, the payment is taken,
     * the response is owed. An exception would turn "the realtime update is
     * late" into a 500 on an operation that succeeded.
     */
    public function test_publish_never_throws_whatever_goes_wrong(): void
    {
        $cases = [
            'a broker that will not accept a connection' => static function (): ScriptedConnection {
                $c = new ScriptedConnection();
                $c->failNextOpen('connection refused');

                return $c;
            },
            'a broker that closes mid-handshake' => static fn (): ScriptedConnection
                => (new ScriptedConnection())->willClose(),
            'a broker that refuses the credentials' => static fn (): ScriptedConnection
                => new ScriptedConnection([Packets::connAck(0x86)]),
            'a broker that evicts this client id' => static fn (): ScriptedConnection
                => new ScriptedConnection([Packets::connAck(0), Packets::disconnect(0x8E)]),
        ];

        foreach ($cases as $label => $build) {
            $adapter = $this->adapter($build());

            self::assertSame(-1, $adapter->publish('documents.42', ['x' => 1]), $label);
        }
    }

    public function test_an_accepted_publish_reports_zero(): void
    {
        $adapter = $this->adapter(new ScriptedConnection([Packets::connAck(0)]));

        // 0, not a count: MQTT reports no subscriber count, and `>= 0` is
        // "accepted" — the only thing this backend knows.
        self::assertSame(0, $adapter->publish('documents.42', ['title' => 'renamed']));
    }

    /**
     * A DEAD BROKER MUST NOT COST EVERY REQUEST THE CONNECT TIMEOUT.
     *
     * Without the cooldown, a broker outage makes every request that publishes
     * an event dial a host that is not answering and wait out the connect
     * timeout. Under PHP-FPM that is every request, so the pool fills with
     * processes blocked in connect() and the site is down — the bus being
     * optional stopped being true the moment it broke.
     */
    public function test_a_failed_connect_suppresses_subsequent_publishes_without_dialling(): void
    {
        $connection = new ScriptedConnection();
        $connection->failNextOpen('connection refused');

        $adapter = $this->adapter($connection, failureCooldown: 30.0);

        self::assertSame(-1, $adapter->publish('a.b', ['x' => 1]));
        self::assertSame(1, $connection->opens, 'one dial');

        // Nine more publishes during the cooldown must not touch the network.
        for ($i = 0; $i < 9; $i++) {
            self::assertSame(-1, $adapter->publish('a.b', ['x' => 1]));
        }

        self::assertSame(1, $connection->opens, 'still one dial, not ten');
    }

    public function test_the_cooldown_expires_and_dialling_resumes(): void
    {
        $now        = 1000.0;
        $connection = new ScriptedConnection();
        $connection->failNextOpen('connection refused');

        $adapter = new MqttPubSub(
            client: new MqttClient($connection, $this->options(), null, static function () use (&$now): float {
                return $now;
            }),
            options: $this->options(failureCooldown: 30.0),
            logger: null,
            monotonic: static function () use (&$now): float { return $now; },
        );

        self::assertSame(-1, $adapter->publish('a.b', ['x' => 1]));
        self::assertSame(1, $connection->opens);

        self::assertSame(-1, $adapter->publish('a.b', ['x' => 1]));
        self::assertSame(1, $connection->opens, 'suppressed');

        // Past the cooldown, and this time the broker answers.
        $now += 31.0;
        $connection->willRead(Packets::connAck(0));

        self::assertSame(0, $adapter->publish('a.b', ['x' => 1]));
        self::assertSame(2, $connection->opens, 'dialled again');
    }

    // ─── Channel / topic translation ────────────────────────────────────────

    /**
     * The kernel's channels are dotted; MQTT topics are slashed. Passing a dot
     * through WOULD work — a dot is a legal topic character — but it collapses
     * the hierarchy, and with it every wildcard: `documents/+` cannot match a
     * topic with no levels in it.
     */
    public function test_a_dotted_channel_becomes_a_slashed_topic(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $adapter    = $this->adapter($connection);

        $adapter->publish('collections.7.documents', ['x' => 1]);

        self::assertStringContainsString('collections/7/documents', $connection->written);
        self::assertStringNotContainsString('collections.7.documents', $connection->written);
    }

    public function test_the_topic_prefix_is_prepended(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $adapter    = $this->adapter($connection, topicPrefix: 'app/');

        $adapter->publish('documents.42', ['x' => 1]);

        self::assertStringContainsString('app/documents/42', $connection->written);
    }

    /**
     * REFUSED RATHER THAN GUESSED. With translation on, a `/` already in the
     * channel would be indistinguishable in the topic from a translated
     * separator — so mapping the topic back to a channel name on the receiving
     * side would produce a DIFFERENT name, and a subscriber would be handed a
     * channel the publisher never used.
     */
    public function test_a_channel_containing_a_slash_is_refused_when_translating(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $adapter    = $this->adapter($connection);

        self::assertSame(-1, $adapter->publish('documents/42', ['x' => 1]));
        self::assertSame('', $connection->written, 'nothing was published');
    }

    /** With translation off, channel names are MQTT topics verbatim. */
    public function test_translation_can_be_disabled(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $adapter    = $this->adapter($connection, topicSeparator: '');

        self::assertSame(0, $adapter->publish('documents/42', ['x' => 1]));
        self::assertStringContainsString('documents/42', $connection->written);

        // And a dot is now just a dot, not a separator.
        $adapter->publish('a.b', ['x' => 1]);
        self::assertStringContainsString('a.b', $connection->written);
    }

    public function test_a_wildcard_channel_is_refused_for_a_publish(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $adapter    = $this->adapter($connection);

        self::assertSame(-1, $adapter->publish('documents.#', ['x' => 1]));
        self::assertSame(-1, $adapter->publish('documents.+', ['x' => 1]));
        self::assertSame('', $connection->written);
    }

    public function test_an_empty_channel_is_refused(): void
    {
        $adapter = $this->adapter(new ScriptedConnection([Packets::connAck(0)]));

        // Deliberately passing values the parameter type forbids: the point of
        // the test is that publish() REFUSES them at runtime rather than
        // relying on a caller having read the signature. Built at runtime so a
        // static analyser does not reject the test for testing the guard.
        /** @var non-empty-string $empty */
        $empty = substr('x', 1, 0) ?: '';
        /** @var non-empty-string $blank */
        $blank = '   ';

        self::assertSame(-1, $adapter->publish($empty, ['x' => 1]));
        self::assertSame(-1, $adapter->publish($blank, ['x' => 1]));
    }

    /**
     * The round trip: a subscriber must be handed the channel name the
     * publisher used, not the topic. This is why a channel with a `/` is
     * refused above — the mapping has to be reversible.
     */
    public function test_a_subscriber_receives_the_channel_name_not_the_topic(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0),
            Packets::subAck(1, [0]),
            Packets::publish('app/collections/7/documents', '{"title":"renamed"}'),
        ]);

        $adapter  = $this->adapter($connection, topicPrefix: 'app/');
        $received = [];

        // stop() from inside the handler, so subscribe() returns rather than
        // looping until the script runs dry.
        $adapter->subscribe(
            ['collections.+.documents'],
            static function (string $channel, array $payload) use (&$received, $adapter): void {
                $received[] = [$channel, $payload];
                $adapter->stop();
            },
        );

        self::assertSame(
            [['collections.7.documents', ['title' => 'renamed']]],
            $received,
            'the prefix is stripped and the slashes become dots again',
        );
    }

    /**
     * On a broker shared with devices most payloads are NOT JSON — protobuf,
     * CBOR, four raw bytes of sensor float. Passing those on as something they
     * are not would hand an application a null it did not ask for.
     */
    public function test_a_non_json_payload_is_dropped_rather_than_passed_on(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0),
            Packets::subAck(1, [0]),
            Packets::publish('sensors/3', "\x41\xAB\x00\x00"),
            Packets::publish('sensors/3', '[1,2,3]'),
            Packets::publish('sensors/3', 'null'),
            Packets::publish('sensors/3', '{"ok":true}'),
        ]);

        $adapter  = $this->adapter($connection);
        $received = [];

        $adapter->subscribe(
            ['sensors.+'],
            static function (string $channel, array $payload) use (&$received, $adapter): void {
                $received[] = $payload;
                $adapter->stop();
            },
        );

        self::assertSame([['ok' => true]], $received, 'only the JSON object got through');
    }

    /**
     * A server told to subscribe to a channel it cannot subscribe to has
     * nothing to do, and starting anyway would hold client connections open
     * and deliver nothing — the exact failure this port's asymmetry prevents.
     */
    public function test_subscribe_throws_on_an_unusable_filter(): void
    {
        $adapter = $this->adapter(new ScriptedConnection([Packets::connAck(0)]));

        $this->expectException(MqttException::class);

        $adapter->subscribe(['a.#.b'], static fn () => null);
    }

    public function test_subscribe_throws_when_given_no_channels(): void
    {
        $adapter = $this->adapter(new ScriptedConnection([Packets::connAck(0)]));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/no channels/');

        $adapter->subscribe([], static fn () => null);
    }

    /**
     * MQTT-SPECIFIC, AND THE REASON THIS LOOP IS NOT A COPY OF THE NATS ONE.
     *
     * `0x8E Session taken over` means another process connected with the same
     * client identifier. Retrying evicts that process, which reconnects and
     * evicts this one — two processes alternating for ever, each looking like a
     * flapping connection, neither holding a usable subscription.
     */
    public function test_a_session_taken_over_disconnect_is_not_retried(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0),
            Packets::subAck(1, [0]),
            Packets::disconnect(0x8E),
        ]);

        $slept   = [];
        $adapter = $this->adapter($connection, sleep: static function (float $s) use (&$slept): void {
            $slept[] = $s;
        });

        try {
            $adapter->subscribe(['a.+'], static fn () => null);
            self::fail('expected the loop to give up');
        } catch (MqttException $e) {
            self::assertStringContainsString('will not be retried', $e->getMessage());
            self::assertStringContainsString('Session Taken Over', $e->getMessage());
        }

        self::assertSame([], $slept, 'it did not back off and try again');
        self::assertSame(1, $connection->opens, 'exactly one connection attempt');
    }

    /**
     * An ordinary drop IS retried, with backoff — and the subscription is
     * re-established by the client's own replay rather than by subscribing
     * again here, which would accumulate a duplicate set per reconnect.
     */
    public function test_an_ordinary_drop_is_retried_with_backoff(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0),
            Packets::subAck(1, [0]),
        ]);
        $connection->willClose();

        $slept   = [];
        $adapter = $this->adapter(
            $connection,
            maxReconnects: 2,
            sleep: static function (float $s) use (&$slept): void { $slept[] = $s; },
        );

        try {
            $adapter->subscribe(['a.+'], static fn () => null);
            self::fail('expected the attempts to run out');
        } catch (MqttException $e) {
            self::assertStringContainsString('could not be kept up after 3 attempt(s)', $e->getMessage());
        }

        self::assertCount(2, $slept, 'it backed off twice before giving up');
        self::assertGreaterThan(0.0, $slept[0]);
    }

    public function test_stop_ends_the_subscription_loop_quietly(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0),
            Packets::subAck(1, [0]),
        ]);

        $adapter = $this->adapter($connection);
        $adapter->stop();

        // stop() before subscribe() means the loop never runs — and it must
        // return rather than throw, because nothing went wrong.
        $adapter->subscribe(['a.+'], static fn () => null);

        self::assertSame(0, $connection->opens);
    }

    public function test_describe_names_the_broker_and_its_limits_without_credentials(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $adapter    = $this->adapter($connection, user: 'secret-user', pass: 'secret-pass');

        $adapter->publish('a.b', ['x' => 1]);

        $description = $adapter->describe();

        self::assertStringContainsString('mqtt', $description);
        self::assertStringContainsString('no subscriber counts', $description);
        self::assertStringNotContainsString('secret-pass', $description, 'never a credential');
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private function adapter(
        ScriptedConnection $connection,
        float $failureCooldown = 30.0,
        int $maxReconnects = 10,
        string $topicPrefix = '',
        string $topicSeparator = '.',
        string $user = '',
        string $pass = '',
        ?\Closure $sleep = null,
    ): MqttPubSub {
        $now = 1000.0;

        $clock = static function () use (&$now): float {
            $now += 0.01;

            return $now;
        };

        $options = $this->options(
            failureCooldown: $failureCooldown,
            maxReconnects: $maxReconnects,
            topicPrefix: $topicPrefix,
            topicSeparator: $topicSeparator,
            user: $user,
            pass: $pass,
        );

        return new MqttPubSub(
            client: new MqttClient($connection, $options, null, $clock),
            options: $options,
            logger: null,
            monotonic: $clock,
            sleep: $sleep ?? static function (float $seconds): void {},
        );
    }

    private function options(
        float $failureCooldown = 30.0,
        int $maxReconnects = 10,
        string $topicPrefix = '',
        string $topicSeparator = '.',
        string $user = '',
        string $pass = '',
    ): ClientOptions {
        return ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1:1883')],
            clientId: ClientId::generate(),
            user: $user,
            pass: $pass,
            connectTimeout: 0.2,
            readTimeout: 0.02,
            maxReconnects: $maxReconnects,
            reconnectWait: 0.01,
            failureCooldown: $failureCooldown,
            topicPrefix: $topicPrefix,
            topicSeparator: $topicSeparator,
        );
    }
}
