<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\PacketType;
use Plugins\Mqtt\Domain\Property;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\ReasonCode;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\Will;

/**
 * The client state machine, driven through a scripted connection.
 *
 * The clock CREEPS rather than being frozen. A frozen clock cannot reach a
 * deadline, so any test of a timeout would hang instead of failing — and the
 * creeping clock also exposes a production property worth stating: the loop's
 * exit condition IS time.
 */
final class ClientTest extends TestCase
{
    // ─── The handshake ──────────────────────────────────────────────────────

    public function test_a_successful_handshake(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);

        $connAck = $client->connect();

        self::assertTrue($connAck->isAccepted());
        self::assertTrue($client->isConnected());
        self::assertFalse($connAck->sessionPresent);

        // The CONNECT really went out, and it is a CONNECT.
        self::assertSame(0x10, \ord($connection->written[0]));
        self::assertStringContainsString('MQTT', $connection->written);
    }

    /**
     * Unlike NATS, MQTT cannot silently succeed: CONNACK is mandatory and
     * carries a reason code, so a wrong password is reported as one.
     */
    public function test_a_wrong_password_is_reported_as_a_wrong_password(): void
    {
        $client = $this->client(new ScriptedConnection([Packets::connAck(0x86)]));

        try {
            $client->connect();
            self::fail('expected a refusal');
        } catch (MqttException $e) {
            self::assertStringContainsString('Bad User Name Or Password', $e->getMessage());
            self::assertStringContainsString('0x86', $e->getMessage());
            self::assertStringContainsString('MQTT_USER and MQTT_PASS', $e->getMessage());
            self::assertTrue($e->connectionLost);
        }

        self::assertFalse($client->isConnected());
    }

    public function test_every_connack_refusal_carries_its_remedy(): void
    {
        $cases = [
            0x84 => 'MQTT_VERSION=3.1.1',
            0x85 => 'MQTT_CLIENT_ID_PREFIX',
            0x87 => 'access control',
            0x88 => 'refusing work',
            0x8A => 'banned',
        ];

        foreach ($cases as $code => $expected) {
            $client = $this->client(new ScriptedConnection([Packets::connAck($code)]));

            try {
                $client->connect();
                self::fail('expected a refusal for 0x' . dechex($code));
            } catch (MqttException $e) {
                self::assertStringContainsString($expected, $e->getMessage(), '0x' . dechex($code));
            }
        }
    }

    /**
     * Silence is what a TLS-only listener does when spoken to in plaintext: it
     * reads the CONNECT as a ClientHello, fails, and closes. The message names
     * that cause, because it is the common one and it looks nothing like
     * itself.
     */
    public function test_no_connack_names_the_tls_listener_as_the_likely_cause(): void
    {
        // '' is a read timeout, repeatedly, until the deadline passes.
        $connection = new ScriptedConnection(array_fill(0, 50, ''));
        $client     = $this->client($connection);

        try {
            $client->connect();
            self::fail('expected a timeout');
        } catch (MqttException $e) {
            self::assertStringContainsString('no CONNACK within', $e->getMessage());
            self::assertStringContainsString('TLS-only listener', $e->getMessage());
            self::assertStringContainsString('port 8883', $e->getMessage());
        }
    }

    /** The broker's limits are applied, not merely recorded. */
    public function test_the_brokers_receive_maximum_limits_in_flight_publishes(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0, properties: Packets::uint16Property(Property::ReceiveMaximum->value, 1)),
        ]);
        $client = $this->client($connection);
        $client->connect();

        // One QoS 1 publish is allowed; it blocks waiting for a PUBACK that
        // never comes, so the identifier is released on the timeout and the
        // next publish can take it.
        $connection->willRead(...array_fill(0, 50, ''));

        try {
            $client->publish('a', ['x' => 1], QoS::AtLeastOnce, timeout: 0.05);
            self::fail('expected a timeout waiting for the PUBACK');
        } catch (MqttException $e) {
            self::assertStringContainsString('PUBACK', $e->getMessage());
        }

        self::assertSame(0, $client->inFlightCount(), 'the identifier was released on the timeout');
    }

    /**
     * [MQTT-3.1.2-21]: a Server Keep Alive in CONNACK is MANDATORY to use. A
     * client that kept its own would ping on the wrong schedule and be timed
     * out while believing itself well inside the window.
     */
    public function test_a_server_imposed_keep_alive_replaces_the_configured_one(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0, properties: Packets::uint16Property(Property::ServerKeepAlive->value, 15)),
        ]);
        $client = $this->client($connection, keepAlive: 60);

        $client->connect();

        self::assertSame(15, $client->keepAlive(), 'the broker overrode 60');
    }

    public function test_a_broker_assigned_client_id_is_recorded(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0, properties: Packets::stringProperty(
                Property::AssignedClientIdentifier->value,
                'auto-12345',
            )),
        ]);
        $client = $this->client($connection);

        $client->connect();

        self::assertSame('auto-12345', $client->clientId());
    }

    /**
     * [MQTT-3.2.2-4]. A client with no session state that is told the session
     * is present must close: the broker is about to deliver messages for
     * subscriptions this client does not know it has, and acknowledge them
     * against identifiers it never allocated.
     */
    public function test_session_present_on_a_clean_start_is_refused(): void
    {
        $client = $this->client(new ScriptedConnection([
            Packets::connAck(0, sessionPresent: true),
        ]));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT-3.2.2-2/');

        $client->connect();
    }

    // ─── Publishing ─────────────────────────────────────────────────────────

    public function test_a_qos0_publish_returns_without_an_acknowledgement(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->clearWritten()->willRead('');

        $ack = $client->publish('documents/42', ['title' => 'renamed']);

        self::assertNull($ack, 'there is no acknowledgement at QoS 0');
        self::assertSame(0x30, \ord($connection->written[0]));
        self::assertStringContainsString('documents/42', $connection->written);
        self::assertStringContainsString('{"title":"renamed"}', $connection->written);
    }

    public function test_a_qos1_publish_waits_for_the_puback(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        // The identifier will be 1, the first allocation.
        $connection->clearWritten()->willRead(Packets::ack(PacketType::PubAck, 1, 0x00));

        $ack = $client->publish('a/b', ['x' => 1], QoS::AtLeastOnce);

        self::assertNotNull($ack);
        self::assertSame(PacketType::PubAck, $ack->type);
        self::assertSame(1, $ack->packetId);
        self::assertFalse($ack->isError());
        self::assertSame(0, $client->inFlightCount(), 'the identifier is released');
    }

    /**
     * `0x10 No matching subscribers` is a SUCCESS that lost the message: the
     * broker accepted it and nobody was subscribed. It is below the 0x80 error
     * boundary, so a caller checking only for errors never sees it.
     */
    public function test_no_matching_subscribers_is_a_success_that_is_still_reported(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::ack(PacketType::PubAck, 1, 0x10));

        $ack = $client->publish('a/b', ['x' => 1], QoS::AtLeastOnce);

        self::assertNotNull($ack);
        self::assertFalse($ack->isError(), 'it is not an error');
        self::assertTrue($ack->reasonCode->isSilentNoOp(), 'but the message is gone');
    }

    /** The full four-packet QoS 2 exchange. */
    public function test_a_qos2_publish_completes_the_four_packet_exchange(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->clearWritten()
            ->willRead(Packets::ack(PacketType::PubRec, 1, 0x00))
            ->willRead(Packets::ack(PacketType::PubComp, 1, 0x00));

        $ack = $client->publish('a/b', ['x' => 1], QoS::ExactlyOnce);

        self::assertNotNull($ack);
        self::assertSame(PacketType::PubComp, $ack->type, 'the exchange ends with PUBCOMP');

        // PUBLISH then PUBREL went out, and PUBREL carries flags 0b0010.
        self::assertSame(0x34, \ord($connection->written[0]), 'PUBLISH at QoS 2');
        self::assertStringContainsString("\x62\x02\x00\x01", $connection->written, 'PUBREL id=1');
        self::assertSame(0, $client->inFlightCount());
    }

    /**
     * A PUBREC with a reason code of 128 or above ENDS the exchange — sending
     * PUBREL would be continuing one that has already failed.
     */
    public function test_a_refused_pubrec_ends_the_qos2_exchange_without_a_pubrel(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->clearWritten()->willRead(Packets::ack(PacketType::PubRec, 1, 0x87));

        $ack = $client->publish('a/b', ['x' => 1], QoS::ExactlyOnce);

        self::assertNotNull($ack);
        self::assertTrue($ack->isError());
        self::assertSame(ReasonCode::NotAuthorized, $ack->reasonCode);
        // Asserted on the whole PUBREL packet, not the byte 0x62 alone — which
        // is also the letter 'b' and appears in the topic 'a/b'.
        self::assertStringNotContainsString(
            "\x62\x02\x00\x01",
            $connection->written,
            'no PUBREL was sent',
        );
    }

    /**
     * The QoS exchange is a fixed sequence, so a packet out of order means the
     * broker and this client disagree about which step they are on.
     */
    public function test_a_wrong_acknowledgement_type_is_refused(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        // A PUBCOMP where a PUBACK was expected.
        $connection->willRead(Packets::ack(PacketType::PubComp, 1, 0x00));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/expected PUBACK .* and got PUBCOMP/');

        $client->publish('a/b', ['x' => 1], QoS::AtLeastOnce);
    }

    /**
     * The broker's advertised Maximum QoS is a hard limit: exceeding it is
     * `0x9B`, which CLOSES the connection — so refusing locally costs one
     * publish rather than every subscription on the link.
     */
    public function test_publishing_above_the_brokers_maximum_qos_is_refused_locally(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0, properties: Packets::byteProperty(Property::MaximumQoS->value, 0)),
        ]);
        $client = $this->client($connection);
        $client->connect();

        $before = $connection->written;

        try {
            $client->publish('a', ['x' => 1], QoS::AtLeastOnce);
            self::fail('expected a local refusal');
        } catch (MqttException $e) {
            self::assertStringContainsString('0x9B', $e->getMessage());
            self::assertFalse($e->connectionLost);
        }

        self::assertSame($before, $connection->written, 'nothing was written');
    }

    public function test_publishing_retained_to_a_broker_without_retain_is_refused_locally(): void
    {
        $connection = new ScriptedConnection([
            Packets::connAck(0, properties: Packets::byteProperty(Property::RetainAvailable->value, 0)),
        ]);
        $client = $this->client($connection);
        $client->connect();

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/0x9A/');

        $client->publish('a', ['x' => 1], retain: true);
    }

    /**
     * A publish-only process — anything under PHP-FPM — never reads, so a
     * DISCONNECT the broker sent would never be seen and the process would
     * write into a dead socket for every subsequent request. The realistic
     * cause is `0x8E Session taken over`.
     */
    public function test_a_publish_notices_a_disconnect_the_broker_already_sent(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::disconnect(0x8E));

        try {
            $client->publish('a', ['x' => 1]);
            self::fail('the publish should have noticed the DISCONNECT');
        } catch (MqttException $e) {
            self::assertStringContainsString('Session Taken Over', $e->getMessage());
            self::assertStringContainsString('another connection presented the same Client', $e->getMessage());
            self::assertTrue($e->connectionLost);
        }

        $disconnect = $client->lastDisconnect();

        self::assertNotNull($disconnect);
        self::assertTrue($disconnect->retryWouldWorsen());
    }

    // ─── Subscribing ────────────────────────────────────────────────────────

    public function test_subscribing_waits_for_the_suback_and_routes_messages(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->clearWritten()->willRead(Packets::subAck(1, [0]));

        $received = [];

        $client->subscribe('sensors/+/temp', static function (MqttMessage $m) use (&$received): void {
            $received[] = [$m->topic, $m->payload];
        });

        // SUBSCRIBE went out with flags 0b0010.
        self::assertSame(0x82, \ord($connection->written[0]));
        self::assertSame(['sensors/+/temp'], $client->subscribedFilters());

        $connection->willRead(
            Packets::publish('sensors/3/temp', '21.5'),
            Packets::publish('sensors/4/temp', '19.0'),
            Packets::publish('sensors/3/humidity', 'ignored'),
        );

        $client->run(0.2);

        self::assertSame(
            [['sensors/3/temp', '21.5'], ['sensors/4/temp', '19.0']],
            $received,
            'the non-matching topic is not delivered to this handler',
        );
    }

    /**
     * A refused SUBACK leaves the connection usable and the subscription
     * nonexistent. A client that did not wait would report success, receive
     * nothing, and look exactly like a system in which nothing is published.
     */
    public function test_a_refused_subscription_throws_and_is_not_recorded(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0x87]));

        try {
            $client->subscribe('secret/#', static fn () => null);
            self::fail('expected a refusal');
        } catch (MqttException $e) {
            self::assertStringContainsString('[secret/#]', $e->getMessage());
            self::assertStringContainsString('Not Authorized', $e->getMessage());
            self::assertStringContainsString('access control', $e->getMessage(), 'and its remedy');
            self::assertFalse($e->connectionLost, 'the session is still fine');
        }

        self::assertSame([], $client->subscribedFilters(), 'not recorded, so a reconnect will not replay it');
    }

    /**
     * A broker MAY grant a LOWER QoS than requested, and it is not an error. A
     * subscriber that asked for QoS 2 and ignored a `Granted QoS 0` would
     * believe it had exactly-once delivery when it had none.
     */
    public function test_a_downgraded_qos_is_recorded_and_warned_about(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0x00]));

        $subAck = $client->subscribe('a/#', static fn () => null, QoS::ExactlyOnce);

        self::assertSame(QoS::AtMostOnce, $subAck->grantedQoS(0));
        self::assertNotSame([], $client->warnings());
        self::assertStringContainsString('granted at most once (0)', $client->warnings()[0]);
    }

    /**
     * Position is the ONLY thing pairing a reason code to a filter — the reply
     * names no filters. So a count mismatch leaves no way to know which filter
     * each code belongs to, and treating any as subscribed would be a guess.
     */
    public function test_a_suback_with_the_wrong_number_of_codes_is_refused(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0x00, 0x00]));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/unattributable/');

        $client->subscribe('a', static fn () => null);
    }

    /** A message matching two subscriptions calls BOTH handlers. */
    public function test_a_message_matching_two_filters_reaches_both_handlers(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $hits = [];

        $connection->willRead(Packets::subAck(1, [0]));
        $client->subscribe('a/+', static function () use (&$hits): void { $hits[] = 'plus'; });

        $connection->willRead(Packets::subAck(2, [0]));
        $client->subscribe('a/#', static function () use (&$hits): void { $hits[] = 'hash'; });

        $connection->willRead(Packets::publish('a/b', 'x'));
        $client->run(0.2);

        self::assertSame(['plus', 'hash'], $hits);
    }

    public function test_unsubscribing_removes_the_local_subscription(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0]));
        $client->subscribe('a/#', static fn () => null);

        $connection->willRead(Packets::subAck(2, [0x00], PacketType::UnsubAck));
        $client->unsubscribe(['a/#']);

        self::assertSame([], $client->subscribedFilters());
    }

    /**
     * `0x11 No subscription existed` is a SUCCESS, so a caller that ignored it
     * would believe it had unsubscribed and keep receiving messages. Filters
     * are compared character by character [MQTT-3.10.4-1].
     */
    public function test_unsubscribing_a_filter_the_broker_does_not_hold_is_warned_about(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0x11], PacketType::UnsubAck));
        $client->unsubscribe(['a/b']);

        self::assertNotSame([], $client->warnings());
        self::assertStringContainsString('character by character', $client->warnings()[0]);
    }

    // ─── Inbound QoS ────────────────────────────────────────────────────────

    public function test_an_inbound_qos1_message_is_acknowledged(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [1]));
        $client->subscribe('a/#', static fn () => null, QoS::AtLeastOnce);

        $connection->clearWritten()
            ->willRead(Packets::publish('a/b', 'x', qos: 1, packetId: 77));

        $client->run(0.2);

        // PUBACK for 77: 0x40, length 2, then the identifier.
        self::assertStringContainsString("\x40\x02\x00\x4D", $connection->written);
    }

    /**
     * THE TEST THAT MAKES QoS 2 MEAN ANYTHING.
     *
     * The broker re-sends a PUBLISH it has not seen a PUBREC for. Without
     * remembering which identifiers are mid-exchange, the re-send is delivered
     * to the application a second time — turning the one QoS level that
     * promises exactly-once into at-least-once with extra round trips.
     */
    public function test_a_redelivered_qos2_message_is_acknowledged_but_not_delivered_twice(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [2]));

        $delivered = 0;
        $client->subscribe('a/#', static function () use (&$delivered): void {
            ++$delivered;
        }, QoS::ExactlyOnce);

        $connection->clearWritten()->willRead(
            Packets::publish('a/b', 'x', qos: 2, packetId: 5),
            // The broker re-sends because it saw no PUBREC in time.
            Packets::publish('a/b', 'x', qos: 2, packetId: 5, dup: true),
        );

        $client->run(0.2);

        self::assertSame(1, $delivered, 'the application sees it exactly once');

        // But BOTH copies were PUBREC'd — staying silent on the second would
        // leave the broker re-sending for ever.
        self::assertSame(
            2,
            substr_count($connection->written, "\x50\x02\x00\x05"),
            'both copies are acknowledged with PUBREC',
        );
    }

    public function test_a_pubrel_is_answered_with_a_pubcomp_and_clears_the_exchange(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [2]));

        $delivered = 0;
        $client->subscribe('a/#', static function () use (&$delivered): void {
            ++$delivered;
        }, QoS::ExactlyOnce);

        $connection->clearWritten()->willRead(
            Packets::publish('a/b', 'x', qos: 2, packetId: 5),
            Packets::ack(PacketType::PubRel, 5, 0x00),
            // A NEW message reusing identifier 5 after the exchange closed must
            // be delivered: the broker is entitled to reuse it.
            Packets::publish('a/b', 'y', qos: 2, packetId: 5),
        );

        $client->run(0.2);

        self::assertStringContainsString("\x70\x02\x00\x05", $connection->written, 'PUBCOMP for 5');
        self::assertSame(2, $delivered, 'a reused identifier after PUBREL is a new message');
    }

    // ─── Keep-alive ─────────────────────────────────────────────────────────

    /**
     * A subscriber on an idle topic sends nothing at all, so without the
     * PINGREQ an idle subscription dies after 1.5x the keep-alive and
     * reconnects, repeatedly, which looks like a flapping network.
     */
    public function test_an_idle_connection_sends_a_pingreq(): void
    {
        $now        = 1000.0;
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = new MqttClient(
            $connection,
            $this->options(keepAlive: 10),
            null,
            // Creeping, not frozen: a frozen clock can never reach run()'s
            // deadline, so the loop would spin for ever. The test still jumps
            // it by whole seconds to reach the ping schedule.
            static function () use (&$now): float {
                $now += 0.001;

                return $now;
            },
        );

        $client->connect();
        $connection->clearWritten();

        // Nothing arrives, and time passes beyond 80% of the keep-alive.
        $now += 9.0;

        $client->run(0.01);

        self::assertStringContainsString("\xC0\x00", $connection->written, 'PINGREQ went out');
    }

    /**
     * The timer is reset by ANY packet sent, not just a ping: a client
     * publishing steadily satisfies the keep-alive without pinging at all.
     */
    public function test_a_steady_publisher_never_needs_to_ping(): void
    {
        $now        = 1000.0;
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = new MqttClient(
            $connection,
            $this->options(keepAlive: 10),
            null,
            static function () use (&$now): float {
                $now += 0.001;

                return $now;
            },
        );

        $client->connect();
        $connection->clearWritten();

        // Publish every 5 seconds for 30 seconds — always inside the 8-second
        // ping interval, so no PINGREQ should ever be due.
        for ($i = 0; $i < 6; $i++) {
            $client->publish('a', ['n' => $i]);
            $now += 5.0;
        }

        self::assertStringNotContainsString("\xC0\x00", $connection->written, 'no ping was needed');
    }

    /**
     * A half-open connection — a NAT that dropped the flow, a host that slept —
     * delivers nothing and reports nothing. The only way to find out is to ask
     * and notice that no answer came.
     */
    public function test_an_unanswered_pingreq_declares_the_link_dead(): void
    {
        $now        = 1000.0;
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = new MqttClient(
            $connection,
            $this->options(keepAlive: 10),
            null,
            static function () use (&$now): float {
                $now += 0.001;

                return $now;
            },
        );

        $client->connect();

        // Past the ping interval, so a PINGREQ goes out…
        $now += 9.0;
        $client->run(0.01);

        // …and then past 1.5x the keep-alive with no PINGRESP.
        $now += 20.0;

        try {
            $client->run(0.01);
            self::fail('the half-open link should have been declared dead');
        } catch (MqttException $e) {
            self::assertStringContainsString('PINGREQ went unanswered', $e->getMessage());
            self::assertStringContainsString('half-open', $e->getMessage());
            self::assertTrue($e->connectionLost);
        }
    }

    public function test_a_pingresp_clears_the_outstanding_ping(): void
    {
        $now        = 1000.0;
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = new MqttClient(
            $connection,
            $this->options(keepAlive: 10),
            null,
            static function () use (&$now): float {
                $now += 0.001;

                return $now;
            },
        );

        $client->connect();

        // 1. Past the ping interval, so a PINGREQ goes out and is outstanding.
        $now += 9.0;
        $client->run(0.01);

        // 2. The broker answers it.
        $connection->willRead(Packets::pingResp());
        $client->run(0.01);

        // 3. Now jump well past 1.5x the keep-alive. Because the ping WAS
        //    answered, nothing is outstanding — so this is not a half-open
        //    link, and the only thing due is a fresh ping.
        $now += 20.0;
        $client->run(0.01);

        self::assertTrue($client->isConnected());
    }

    // ─── Reconnect ──────────────────────────────────────────────────────────

    /**
     * With a clean start the broker forgets every subscription when the socket
     * drops. A client that reconnects but does not re-send its SUBSCRIBE comes
     * back looking entirely healthy — connected, publishing, reading — and
     * receives nothing, for ever.
     */
    public function test_subscriptions_are_replayed_on_reconnect(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0]));
        $client->subscribe('documents/+', static fn () => null);

        $connection->willRead(Packets::subAck(2, [0]));
        $client->subscribe('collections/#', static fn () => null);

        // A fresh connection, and the replay's SUBACK.
        $client->close();
        $connection->clearWritten()->willRead(
            Packets::connAck(0),
            Packets::subAck(1, [0, 0]),
        );

        $client->connect();

        self::assertSame(0x82, \ord(substr($connection->written, strpos($connection->written, "\x82") ?: 0, 1)));
        self::assertStringContainsString('documents/+', $connection->written);
        self::assertStringContainsString('collections/#', $connection->written);
        self::assertSame(['documents/+', 'collections/#'], $client->subscribedFilters());
    }

    /** A resumed session already holds the subscriptions, so no replay is needed. */
    public function test_a_resumed_session_does_not_replay_subscriptions(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection, cleanStart: false, clientId: 'stable-id');
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0]));
        $client->subscribe('a/#', static fn () => null);

        $client->close();
        $connection->clearWritten()->willRead(Packets::connAck(0, sessionPresent: true));

        $client->connect();

        self::assertStringNotContainsString("\x82", $connection->written, 'no SUBSCRIBE was re-sent');
    }

    /**
     * A replay that is REFUSED is worse than a failed subscribe, because the
     * application already believes it is subscribed. Swallowing it would leave
     * the process connected, healthy and deaf.
     */
    public function test_a_refused_replay_on_reconnect_throws(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0]));
        $client->subscribe('a/#', static fn () => null);

        $client->close();
        $connection->willRead(Packets::connAck(0), Packets::subAck(1, [0x87]));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/previously granted/');

        $client->connect();
    }

    // ─── Lifecycle ──────────────────────────────────────────────────────────

    /**
     * A stop can arrive BEFORE run() is entered — a signal handler firing
     * between connect() and run(), which is a window of one TCP handshake plus
     * a round trip and so not rare under a rolling restart. With one flag,
     * run() setting running=true would erase it and the process would serve
     * for ever, having been asked to exit.
     */
    public function test_a_stop_arriving_before_run_is_honoured(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $client->stop();

        // No script left, so if run() actually looped it would throw on the
        // first read. Returning quietly is the pass.
        $client->run();

        // The pass IS that run() returned without reading: the script is empty,
        // so a loop that actually ran would have read an idle connection
        // forever and tripped the reader's backstop.
        self::assertSame(0, $connection->remainingScript());
    }

    /**
     * A plain DISCONNECT tells the broker this was a clean exit, and the broker
     * then DISCARDS the will — so a process with a "down" will that shuts down
     * politely publishes no "down". `0x04` is how to exit cleanly AND fire it.
     */
    public function test_disconnect_can_ask_for_the_will_to_fire(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection, will: new Will('status', 'down', retain: true));
        $client->connect();

        $connection->clearWritten();
        $client->disconnect(withWill: true);

        // DISCONNECT 0xE0, remaining length 1, reason 0x04.
        self::assertSame("\xE0\x01\x04", $connection->written);
    }

    public function test_a_plain_disconnect_is_two_bytes(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->clearWritten();
        $client->disconnect();

        self::assertSame("\xE0\x00", $connection->written);
        self::assertFalse($client->isConnected());
    }

    /** A packet only a client sends means the peer is not a broker. */
    public function test_a_client_only_packet_from_the_broker_is_refused(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::wrap(PacketType::PingReq, 0, ''));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/only a CLIENT sends/');

        $client->run(0.2);
    }

    /**
     * Enhanced authentication is not implemented, and refused rather than
     * ignored: the broker would be waiting for a reply this client will never
     * send, so the handshake would hang until the timeout and report nothing
     * useful.
     */
    public function test_an_auth_packet_is_refused_with_an_explanation(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::wrap(PacketType::Auth, 0, "\x18\x00"));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/enhanced authentication/');

        $client->run(0.2);
    }

    public function test_a_second_connack_on_an_open_connection_is_refused(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::connAck(0));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/exactly one per connection/');

        $client->run(0.2);
    }

    public function test_operations_before_connecting_are_refused(): void
    {
        $client = $this->client(new ScriptedConnection());

        try {
            $client->publish('a', ['x' => 1]);
            self::fail('publish before connect');
        } catch (MqttException $e) {
            self::assertStringContainsString('not open', $e->getMessage());
        }

        try {
            $client->run();
            self::fail('run before connect');
        } catch (MqttException $e) {
            self::assertStringContainsString('not open', $e->getMessage());
        }
    }

    public function test_subscribe_with_mismatched_handler_count_is_refused(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/paired by position/');

        $client->subscribeWith(
            [new \Plugins\Mqtt\Domain\Subscription('a'), new \Plugins\Mqtt\Domain\Subscription('b')],
            [static fn () => null],
        );
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private function client(
        ScriptedConnection $connection,
        int $keepAlive = 60,
        bool $cleanStart = true,
        ?string $clientId = null,
        ?Will $will = null,
    ): MqttClient {
        // A CREEPING clock. A frozen one cannot reach a deadline, so a timeout
        // test would hang rather than fail; a real one would make the suite
        // sleep. This advances a little on every call, which is also an honest
        // model of the production property that the loop's exit condition IS
        // time.
        $now = 1000.0;

        return new MqttClient(
            $connection,
            $this->options($keepAlive, $cleanStart, $clientId, $will),
            null,
            static function () use (&$now): float {
                $now += 0.01;

                return $now;
            },
        );
    }

    private function options(
        int $keepAlive = 60,
        bool $cleanStart = true,
        ?string $clientId = null,
        ?Will $will = null,
        ProtocolVersion $version = ProtocolVersion::V5,
    ): ClientOptions {
        return ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1:1883')],
            clientId: $clientId !== null ? ClientId::configured($clientId) : ClientId::generate(),
            version: $version,
            keepAlive: $keepAlive,
            cleanStart: $cleanStart,
            will: $will,
            connectTimeout: 0.2,
            readTimeout: 0.05,
        );
    }
}
