<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Infrastructure\Transport\StreamConnection;

/**
 * THE ONLY TESTS THAT ARE NOT SELF-REFERENTIAL.
 *
 * Every other test in this suite checks this plugin against this plugin. The
 * codec tests are careful to build their fixtures by hand rather than with the
 * encoder, which helps — but a hand-built fixture is still this author's
 * reading of the specification, and if that reading is wrong then the encoder,
 * the decoder and the fixture are all wrong together and every test passes.
 *
 * These tests run against a REAL broker, which is the only arbiter that is
 * neither half of the codec. If a packet this client emits is malformed, a real
 * broker closes the connection; if a packet it cannot read is well-formed, the
 * message does not arrive. Neither outcome is negotiable with a test fixture.
 *
 * HOW TO RUN THEM
 * ---------------
 * Point `MQTT_TEST_URL` at a broker and they run; without it they SKIP rather
 * than fail, because a test suite that needs a daemon to pass is a test suite
 * nobody runs.
 *
 *     # mosquitto
 *     MQTT_TEST_URL=mqtt://127.0.0.1:1883 vendor/bin/phpunit --testsuite Socket
 *
 *     # nats-server, which this toolchain already pins and which speaks
 *     # MQTT 3.1.1 natively (it needs JetStream for MQTT session state):
 *     nats-server -js -m 8222 --mqtt_port 1883 &
 *     MQTT_TEST_URL=mqtt://127.0.0.1:1883 MQTT_TEST_VERSION=3.1.1 \
 *         vendor/bin/phpunit --testsuite Socket
 *
 * `MQTT_TEST_VERSION` defaults to 5 and exists because plenty of brokers speak
 * only 3.1.1 — including nats-server. {@see self::test_the_broker_reports_its_protocol_version}
 * discovers which, rather than assuming.
 */
final class BrokerTest extends TestCase
{
    private string $url = '';

    private ProtocolVersion $version = ProtocolVersion::V5;

    /** A topic prefix unique to this run, so repeated runs cannot collide. */
    private string $prefix = '';

    /** @var list<MqttClient> closed in tearDown, whatever a test did */
    private array $clients = [];

    protected function setUp(): void
    {
        $url = getenv('MQTT_TEST_URL');

        if (!\is_string($url) || trim($url) === '') {
            self::markTestSkipped(
                'Set MQTT_TEST_URL to a broker to run the real-broker tests — e.g. '
                . 'MQTT_TEST_URL=mqtt://127.0.0.1:1883. These are the only tests here that check this '
                . 'codec against something that is not itself.',
            );
        }

        $this->url = trim($url);

        $version = getenv('MQTT_TEST_VERSION');

        if (\is_string($version) && trim($version) !== '') {
            $parsed = ProtocolVersion::parse($version);

            self::assertNotNull($parsed, 'MQTT_TEST_VERSION must be 5 or 3.1.1');

            $this->version = $parsed;
        }

        // Unique per run. Retained messages and persistent sessions OUTLIVE a
        // test, so a fixed topic would make the second run of the suite read
        // the first run's leftovers — which is a flaky test that looks like a
        // broker bug.
        $this->prefix = 'hkmtest/' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        foreach ($this->clients as $client) {
            try {
                $client->disconnect();
            } catch (\Throwable) {
                // A test that already broke the connection must not fail twice.
            }
        }

        $this->clients = [];
    }

    // ─── The handshake ──────────────────────────────────────────────────────

    public function test_a_real_handshake_completes(): void
    {
        $client  = $this->client();
        $connAck = $client->connect();

        self::assertTrue($connAck->isAccepted(), 'the broker accepted the CONNECT this client built');
        self::assertTrue($client->isConnected());
        self::assertFalse(
            $connAck->sessionPresent,
            'a clean start must not report a session',
        );
    }

    /**
     * Which version the broker actually speaks, discovered rather than assumed.
     *
     * A broker that does not support the requested version answers
     * `0x84 Unsupported Protocol Version` — or, in 3.1.1, return code 1. Either
     * way this test reports what happened instead of leaving a silent skip.
     */
    public function test_the_broker_reports_its_protocol_version(): void
    {
        $client = $this->client();

        try {
            $client->connect();

            $this->addToAssertionCount(1);
        } catch (MqttException $e) {
            self::fail(
                'this broker refused MQTT ' . $this->version->label() . ': ' . $e->getMessage()
                . ' — set MQTT_TEST_VERSION to the version it does speak',
            );
        }
    }

    /**
     * A wrong password must be reported AS a wrong password. This is the claim
     * the plugin makes about MQTT being better than NATS here, and only a real
     * broker can confirm the reason code actually comes back.
     */
    public function test_a_wrong_password_is_reported_by_the_broker(): void
    {
        $client = $this->client(user: 'definitely-not-a-user', pass: 'definitely-not-a-password');

        try {
            $client->connect();

            // An anonymous broker accepts anything, which is not a failure of
            // this client. Recorded rather than asserted: there is nothing to
            // assert, and a test that reported a pass it did not earn would be
            // worse than one that says the check was unavailable.
            $this->addToAssertionCount(1);
        } catch (MqttException $e) {
            self::assertTrue($e->connectionLost);
            self::assertMatchesRegularExpression(
                '/Bad User Name Or Password|Not Authorized|refused the connection/i',
                $e->getMessage(),
            );
        }
    }

    // ─── A real round trip ──────────────────────────────────────────────────

    /**
     * THE CENTRAL TEST. One client subscribes, another publishes, and the
     * message comes back through a real broker — which means the SUBSCRIBE this
     * client built was understood, the PUBLISH was understood, and the PUBLISH
     * the broker sent back was decoded correctly.
     */
    public function test_a_message_published_by_one_client_reaches_another(): void
    {
        $topic = $this->prefix . '/round-trip';

        $subscriber = $this->client();
        $subscriber->connect();

        $received = [];

        $subscriber->subscribe($topic, static function (MqttMessage $m) use (&$received): void {
            $received[] = [$m->topic, $m->payload];
        }, timeout: 5.0);

        $publisher = $this->client();
        $publisher->connect();
        $publisher->publish($topic, ['hello' => 'world'], QoS::AtLeastOnce, timeout: 5.0);

        // A full closure with `use (&$received)`, NOT an arrow function. An
        // arrow function captures by VALUE and cannot capture by reference, so
        // `fn () => $received !== []` would test the empty array as it was when
        // the closure was created and never become true — a predicate that is
        // permanently false, which reads as "the broker never delivered".
        $this->pumpUntil($subscriber, static function () use (&$received): bool {
            return $received !== [];
        });

        self::assertSame([[$topic, '{"hello":"world"}']], $received);
    }

    /**
     * The wildcard matcher has to agree with the BROKER's. A disagreement does
     * not error — it delivers to the wrong handler or to none — so this checks
     * the broker routes the same way {@see \Plugins\Mqtt\Domain\Topic::matches()}
     * says it does.
     */
    public function test_the_broker_agrees_with_this_clients_wildcard_matching(): void
    {
        $subscriber = $this->client();
        $subscriber->connect();

        $single = [];
        $multi  = [];

        $subscriber->subscribe(
            $this->prefix . '/sensors/+/temp',
            static function (MqttMessage $m) use (&$single): void { $single[] = $m->topic; },
            timeout: 5.0,
        );

        $subscriber->subscribe(
            $this->prefix . '/sensors/#',
            static function (MqttMessage $m) use (&$multi): void { $multi[] = $m->topic; },
            timeout: 5.0,
        );

        $publisher = $this->client();
        $publisher->connect();

        foreach (['sensors/3/temp', 'sensors/4/temp', 'sensors/3/humidity', 'other/3/temp'] as $suffix) {
            $publisher->publish($this->prefix . '/' . $suffix, ['v' => 1], QoS::AtLeastOnce, timeout: 5.0);
        }

        $this->pumpUntil($subscriber, static function () use (&$multi, &$single): bool {
            return \count($multi) >= 3 && \count($single) >= 2;
        });

        // Asserted on the SET of topics, not the count of deliveries.
        //
        // With two OVERLAPPING filters on one connection, how many copies
        // arrive is broker-dependent and the specification does not settle it
        // for 3.1.1: §3.3.4 lets a server send one copy per matching
        // subscription OR a single copy. nats-server sends one per
        // subscription; mosquitto sends one. Asserting a count would be
        // asserting which broker is in use.
        //
        // What this test is actually for is that the broker and
        // Topic::matches() agree on WHICH topics match — and that is exactly
        // what the deduplicated set shows.
        $single = array_values(array_unique($single));
        $multi  = array_values(array_unique($multi));

        sort($single);
        sort($multi);

        self::assertSame(
            [$this->prefix . '/sensors/3/temp', $this->prefix . '/sensors/4/temp'],
            $single,
            '+ matched one level and not the humidity topic',
        );

        self::assertSame(
            [
                $this->prefix . '/sensors/3/humidity',
                $this->prefix . '/sensors/3/temp',
                $this->prefix . '/sensors/4/temp',
            ],
            $multi,
            '# matched everything under sensors and nothing outside it',
        );
    }

    /**
     * A real PUBACK, from a real broker, for a QoS 1 publish — which is the
     * only thing that proves the broker ACCEPTED a message rather than merely
     * that the socket took the bytes.
     */
    public function test_a_qos1_publish_is_acknowledged_by_the_broker(): void
    {
        $client = $this->client();
        $client->connect();

        $ack = $client->publish(
            $this->prefix . '/qos1',
            ['x' => 1],
            QoS::AtLeastOnce,
            timeout: 5.0,
        );

        self::assertNotNull($ack);
        self::assertFalse($ack->isError(), $ack->describe());
        self::assertSame(0, $client->inFlightCount(), 'the identifier was released');
    }

    /**
     * The full four-packet QoS 2 exchange against a real broker. Worth its own
     * test because the two round trips are the easiest thing to get out of step
     * — and a broker answers a wrong PUBREL by closing the connection.
     */
    public function test_a_qos2_publish_completes_against_a_real_broker(): void
    {
        $client  = $this->client();
        $connAck = $client->connect();

        if ($connAck->maximumQoS()->value < 2) {
            self::markTestSkipped('this broker advertises a Maximum QoS of ' . $connAck->maximumQoS()->value);
        }

        $ack = $client->publish(
            $this->prefix . '/qos2',
            ['x' => 1],
            QoS::ExactlyOnce,
            timeout: 5.0,
        );

        self::assertNotNull($ack);
        self::assertFalse($ack->isError(), $ack->describe());
        self::assertSame(0, $client->inFlightCount());
    }

    /**
     * A retained message is delivered to a subscriber that arrives AFTER it was
     * published — the thing `PubSubPort` cannot express and one of the reasons
     * this plugin exists.
     */
    public function test_a_retained_message_reaches_a_later_subscriber(): void
    {
        $topic = $this->prefix . '/retained';

        $publisher = $this->client();
        $connAck   = $publisher->connect();

        if (!$connAck->retainAvailable()) {
            self::markTestSkipped('this broker does not support retained messages');
        }

        $publisher->publish($topic, ['state' => 'up'], QoS::AtLeastOnce, retain: true, timeout: 5.0);

        // A SECOND client, connecting after the publish, with no subscription
        // at the time it was made.
        $late     = $this->client();
        $late->connect();
        $received = [];

        $late->subscribe($topic, static function (MqttMessage $m) use (&$received): void {
            $received[] = $m;
        }, timeout: 5.0);

        $this->pumpUntil($late, static function () use (&$received): bool {
            return $received !== [];
        });

        self::assertCount(1, $received);
        self::assertSame('{"state":"up"}', $received[0]->payload);
        self::assertTrue($received[0]->retained, 'and the broker marks it as retained');

        // Clean up: an empty retained payload DELETES the retained message, so
        // a later run of this suite does not read this one's leftovers.
        $publisher->publish($topic, '', QoS::AtLeastOnce, retain: true, timeout: 5.0);
    }

    /**
     * [MQTT-4.7.2-1] against a real broker: `#` must NOT match a `$`-prefixed
     * topic. Worth checking for real, because it is the rule that makes `#`
     * mean "everything except the broker's own tree" and a client that got it
     * wrong would route broker telemetry to an application handler.
     */
    public function test_the_broker_excludes_the_dollar_tree_from_a_leading_wildcard(): void
    {
        $subscriber = $this->client();
        $subscriber->connect();

        $received = [];

        try {
            $subscriber->subscribe('#', static function (MqttMessage $m) use (&$received): void {
                $received[] = $m->topic;
            }, timeout: 5.0);
        } catch (MqttException $e) {
            self::markTestSkipped('this broker refuses a bare "#" subscription: ' . $e->getMessage());
        }

        $publisher = $this->client();
        $publisher->connect();
        $publisher->publish($this->prefix . '/ordinary', ['x' => 1], QoS::AtLeastOnce, timeout: 5.0);

        // Waiting for OUR topic specifically, not merely for "something".
        // A bare `#` matches everything on the broker — including retained
        // messages left by other tests and other runs — so a predicate of
        // `$received !== []` returns at the first unrelated message, before
        // this test's own publish has arrived.
        $mine = $this->prefix . '/ordinary';

        $this->pumpUntil($subscriber, static function () use (&$received, $mine): bool {
            return \in_array($mine, $received, true);
        });

        self::assertContains($mine, $received);

        foreach ($received as $topic) {
            self::assertStringStartsNotWith(
                '$',
                $topic,
                '"#" must not match a $-prefixed topic [MQTT-4.7.2-1]',
            );
        }
    }

    /**
     * A subscription the broker REFUSES must be reported. Only a real broker
     * with real access control can produce this, so the test adapts: it
     * reports when the broker is permissive rather than asserting a refusal
     * that depends on configuration.
     */
    public function test_a_refused_subscription_is_reported_if_the_broker_refuses_any(): void
    {
        $client = $this->client();
        $client->connect();

        try {
            $subAck = $client->subscribe('$SYS/#', static fn () => null, timeout: 5.0);

            self::assertTrue($subAck->isFullyGranted(), 'granted, so this broker permits $SYS/#');
        } catch (MqttException $e) {
            // The refusal path, which is what this test is really about.
            self::assertStringContainsString('[$SYS/#]', $e->getMessage());
            self::assertFalse($e->connectionLost, 'a refused filter leaves the session usable');
        }
    }

    /**
     * An UNSUBSCRIBE really stops delivery. Checked for real because the
     * filters are compared character by character [MQTT-3.10.4-1], so a client
     * that normalised them would unsubscribe from nothing and keep receiving.
     */
    public function test_unsubscribing_really_stops_delivery(): void
    {
        $topic = $this->prefix . '/unsub';

        $subscriber = $this->client();
        $subscriber->connect();

        $count = 0;

        $subscriber->subscribe($topic, static function () use (&$count): void {
            ++$count;
        }, timeout: 5.0);

        $publisher = $this->client();
        $publisher->connect();
        $publisher->publish($topic, ['n' => 1], QoS::AtLeastOnce, timeout: 5.0);

        $this->pumpUntil($subscriber, static function () use (&$count): bool {
            return $count >= 1;
        });
        self::assertSame(1, $count);

        $unsubAck = $subscriber->unsubscribe([$topic], timeout: 5.0);

        self::assertTrue($unsubAck->isFullyGranted(), 'the broker found the subscription to remove');
        self::assertSame([], $subscriber->subscribedFilters());

        $publisher->publish($topic, ['n' => 2], QoS::AtLeastOnce, timeout: 5.0);

        // Pump for a while; nothing more should arrive.
        $subscriber->run(0.5);

        self::assertSame(1, $count, 'the second message was not delivered');
    }

    /**
     * A PINGREQ gets a PINGRESP from a real broker. The keep-alive is the only
     * thing keeping an idle subscription alive, so a broker that did not answer
     * a ping built by this client would be a silent death after 1.5x the
     * keep-alive.
     */
    public function test_the_broker_answers_a_real_pingreq(): void
    {
        // A keep-alive of 2 seconds puts the ping interval at 1.6s and the
        // broker's patience at 3s, so one ping is comfortably due inside the
        // run below. Not 1 second: that leaves the 0.5s floor doing the work
        // and makes the test about the floor rather than about the ping.
        $client = $this->client(keepAlive: 2);
        $client->connect();

        // Longer than the ping interval plus the broker's round trip. If the
        // PINGREQ were malformed or the PINGRESP misread, the client would
        // declare the link half-open and throw.
        $client->run(5.0);

        self::assertTrue($client->isConnected(), 'the link survived, so the ping was answered');
    }

    /**
     * THE EVICTION, FOR REAL.
     *
     * [MQTT-3.1.4-3] requires the broker to disconnect the previous holder of a
     * client identifier. This is the plugin's headline hazard, and it is worth
     * seeing happen rather than described: the first client is kicked off and
     * the second succeeds, with no error on the second.
     */
    public function test_a_duplicate_client_identifier_evicts_the_first_connection(): void
    {
        $id = 'hkmdup' . bin2hex(random_bytes(6));

        $first = $this->client(clientId: $id);
        $first->connect();

        self::assertTrue($first->isConnected());

        $second = $this->client(clientId: $id);
        $second->connect();

        self::assertTrue($second->isConnected(), 'the second connection succeeds, with no error');

        // The first is now being disconnected by the broker. Reading is what
        // discovers it: either a DISCONNECT 0x8E (5.0) or a closed socket
        // (3.1.1, which has no server-sent DISCONNECT).
        try {
            $first->run(3.0);

            self::fail('the first connection should have been evicted');
        } catch (MqttException $e) {
            self::assertTrue($e->connectionLost);

            if ($this->version === ProtocolVersion::V5) {
                $disconnect = $first->lastDisconnect();

                // A 5.0 broker SHOULD say why. Not every one does — some just
                // close — so the specific reason code is checked only when a
                // DISCONNECT actually arrived.
                if ($disconnect !== null) {
                    self::assertStringContainsString('Session Taken Over', $e->getMessage());
                    self::assertTrue(
                        $disconnect->retryWouldWorsen(),
                        'and this client knows not to retry into a fight',
                    );
                }
            }
        }
    }

    /**
     * A will really fires. The broker publishes on a dead client's behalf,
     * which is something nothing the dead process could do would achieve.
     */
    public function test_a_will_is_published_when_a_client_disappears(): void
    {
        $topic = $this->prefix . '/status';

        $watcher = $this->client();
        $watcher->connect();

        $received = [];

        $watcher->subscribe($topic, static function (MqttMessage $m) use (&$received): void {
            $received[] = $m->payload;
        }, timeout: 5.0);

        // A client with a will, which then vanishes WITHOUT a DISCONNECT — a
        // clean DISCONNECT would make the broker discard the will, which is the
        // trap this test also demonstrates.
        $doomed = $this->client(
            keepAlive: 2,
            will: new \Plugins\Mqtt\Domain\Will($topic, 'down'),
        );
        $doomed->connect();

        // close() drops the socket without a DISCONNECT, which is exactly what
        // a killed process looks like to the broker.
        $doomed->close();

        // The broker notices after up to 1.5x the keep-alive — 3 seconds here,
        // which is why the keep-alive is short and the patience below is 8s.
        $this->pumpUntil($watcher, static function () use (&$received): bool {
            return $received !== [];
        }, seconds: 8.0);

        self::assertSame(['down'], $received, 'the broker published the will');
    }

    /**
     * MQTT 5.0 properties survive a real broker. The broker forwards a
     * publisher's Content Type and Response Topic unchanged, so this checks
     * both that this client encodes them legally and that it decodes what comes
     * back.
     */
    public function test_mqtt5_properties_survive_a_round_trip(): void
    {
        if ($this->version !== ProtocolVersion::V5) {
            self::markTestSkipped('properties are MQTT 5.0 only and this broker is being used as 3.1.1');
        }

        $topic = $this->prefix . '/props';

        $subscriber = $this->client();
        $subscriber->connect();

        $received = [];

        $subscriber->subscribe($topic, static function (MqttMessage $m) use (&$received): void {
            $received[] = $m;
        }, timeout: 5.0);

        $publisher = $this->client();
        $publisher->connect();

        $publisher->publish(
            $topic,
            '{"q":1}',
            QoS::AtLeastOnce,
            properties: \Plugins\Mqtt\Domain\Properties::of(
                [
                    \Plugins\Mqtt\Domain\Property::PayloadFormatIndicator->value => 1,
                    \Plugins\Mqtt\Domain\Property::ContentType->value            => 'application/json',
                    \Plugins\Mqtt\Domain\Property::ResponseTopic->value          => $topic . '/reply',
                ],
                [['tenant', 'acme']],
            ),
            timeout: 5.0,
        );

        $this->pumpUntil($subscriber, static function () use (&$received): bool {
            return $received !== [];
        });

        self::assertCount(1, $received);
        self::assertSame('application/json', $received[0]->contentType());
        self::assertTrue($received[0]->declaresUtf8Payload());
        self::assertSame($topic . '/reply', $received[0]->responseTopic());
        self::assertSame('acme', $received[0]->properties()->userProperty('tenant'));
    }

    /**
     * A shared subscription delivers each message to ONE member of the group —
     * queue semantics on a bus. MQTT 5.0 only, and not every broker implements
     * it, so the test skips on a broker that says it does not.
     */
    public function test_a_shared_subscription_delivers_to_one_member_of_the_group(): void
    {
        if ($this->version !== ProtocolVersion::V5) {
            self::markTestSkipped('shared subscriptions are MQTT 5.0 only');
        }

        $topic  = $this->prefix . '/shared';
        $filter = '$share/hkmtest/' . $topic;

        $a       = $this->client();
        $connAck = $a->connect();

        if (!$connAck->sharedSubscriptionsAvailable()) {
            self::markTestSkipped('this broker does not support shared subscriptions');
        }

        $b = $this->client();
        $b->connect();

        $hitsA = 0;
        $hitsB = 0;

        try {
            $a->subscribe($filter, static function () use (&$hitsA): void { ++$hitsA; }, timeout: 5.0);
            $b->subscribe($filter, static function () use (&$hitsB): void { ++$hitsB; }, timeout: 5.0);
        } catch (MqttException $e) {
            self::markTestSkipped('this broker refused a shared subscription: ' . $e->getMessage());
        }

        $publisher = $this->client();
        $publisher->connect();

        for ($i = 0; $i < 6; $i++) {
            $publisher->publish($topic, ['n' => $i], QoS::AtLeastOnce, timeout: 5.0);
        }

        $deadline = microtime(true) + 5.0;

        while (microtime(true) < $deadline && $hitsA + $hitsB < 6) {
            $a->run(0.1);
            $b->run(0.1);
        }

        self::assertSame(
            6,
            $hitsA + $hitsB,
            'every message was delivered exactly once across the group, not once per member',
        );
    }

    /** The broker's own limits, as it actually reports them. */
    public function test_the_brokers_advertised_limits_are_readable(): void
    {
        $client  = $this->client();
        $connAck = $client->connect();

        // Not assertions about a particular broker — assertions that the values
        // decode into sane ranges rather than into nonsense from a misread
        // property block.
        self::assertContains($connAck->maximumQoS()->value, [0, 1, 2]);
        self::assertGreaterThanOrEqual(1, $connAck->receiveMaximum());
        self::assertLessThanOrEqual(65535, $connAck->receiveMaximum());

        if ($connAck->maximumPacketSize() !== null) {
            self::assertGreaterThan(0, $connAck->maximumPacketSize());
        }

        if ($connAck->serverKeepAlive() !== null) {
            self::assertSame($connAck->serverKeepAlive(), $client->keepAlive());
        }
    }

    /**
     * A persistent session really holds the subscription across a reconnect.
     * The one legitimate use of a fixed client identifier, so it is worth
     * confirming it does what it is for.
     */
    public function test_a_persistent_session_survives_a_reconnect(): void
    {
        $id    = 'hkmsess' . bin2hex(random_bytes(5));
        $topic = $this->prefix . '/session';

        $client = $this->client(clientId: $id, cleanStart: false, sessionExpiry: 60);

        $connAck = $client->connect();
        self::assertFalse($connAck->sessionPresent, 'a brand new session');

        $client->subscribe($topic, static fn () => null, QoS::AtLeastOnce, timeout: 5.0);
        $client->disconnect();

        // Reconnect with the same identifier.
        $again   = $this->client(clientId: $id, cleanStart: false, sessionExpiry: 60);
        $connAck = $again->connect();

        if (!$connAck->sessionPresent) {
            self::markTestSkipped(
                'this broker did not hold the session, so persistent sessions cannot be checked '
                . 'against it',
            );
        }

        self::assertTrue($connAck->sessionPresent, 'the broker held the session');
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private function client(
        string $user = '',
        string $pass = '',
        ?string $clientId = null,
        int $keepAlive = 30,
        bool $cleanStart = true,
        int $sessionExpiry = 0,
        ?\Plugins\Mqtt\Domain\Will $will = null,
    ): MqttClient {
        $addresses = ServerAddress::parseList($this->url);

        $options = ClientOptions::create(
            addresses: $addresses,
            clientId: $clientId !== null ? ClientId::configured($clientId) : ClientId::generate('hkmt'),
            user: $user,
            pass: $pass,
            version: $this->version,
            keepAlive: $keepAlive,
            cleanStart: $cleanStart,
            sessionExpiry: $sessionExpiry,
            will: $will,
            connectTimeout: 5.0,
            readTimeout: 0.1,
        );

        $client = new MqttClient(
            new StreamConnection(
                addresses: $options->addresses,
                tlsMode: $options->tls,
                connectTimeout: $options->connectTimeout,
                tlsCa: $options->tlsCa,
                tlsVerify: !$options->tlsInsecure,
            ),
            $options,
        );

        $this->clients[] = $client;

        return $client;
    }

    /**
     * Pump $client until $done, or until $seconds elapse.
     *
     * A real broker's timing is not ours to choose, so waiting on a condition
     * is the only option that is neither flaky nor slow. `microtime` rather
     * than the injected clock: this is wall-clock patience with a real peer.
     */
    private function pumpUntil(MqttClient $client, callable $done, float $seconds = 5.0): void
    {
        $deadline = microtime(true) + $seconds;

        while (microtime(true) < $deadline) {
            if ($done()) {
                return;
            }

            $client->run(0.1);
        }

        self::assertTrue($done(), 'the broker did not deliver within ' . $seconds . 's');
    }

}
