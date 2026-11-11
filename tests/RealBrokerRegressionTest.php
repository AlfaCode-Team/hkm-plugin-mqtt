<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Decoder;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\PacketReader;
use Plugins\Mqtt\Domain\PacketType;
use Plugins\Mqtt\Domain\Property;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\RawPacket;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\VarInt;

/**
 * Five bugs a REAL broker found, pinned so they cannot come back.
 *
 * Every one of these passed the whole in-memory suite. They are here as a
 * group, rather than filed away in the test for whichever class they touch,
 * because what they have in common is more instructive than what they are: all
 * five were invisible to tests written from this author's reading of the
 * specification, and all five surfaced within minutes of pointing the client at
 * a broker nobody here wrote.
 *
 * `BrokerTest` is where that happens, and it SKIPS without `MQTT_TEST_URL` —
 * so these exist to keep the findings covered on an ordinary run.
 */
final class RealBrokerRegressionTest extends TestCase
{
    /**
     * BUG 1 — RETAINED MESSAGES WERE ALL BEING LOST.
     *
     * A broker sends a retained message IMMEDIATELY after the SUBACK, and the
     * two routinely arrive in the SAME TCP segment. The client recorded a
     * subscription only after `awaitSubAck()` returned — so the PUBLISH was
     * dispatched first, found no matching subscription, and was dropped.
     *
     * Since that is exactly when retained messages arrive, the effect was that
     * essentially every retained message was lost, while the subscription
     * reported success. The fix records the subscription before the SUBSCRIBE
     * goes out.
     */
    public function test_a_retained_message_arriving_with_the_suback_is_delivered(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        // ONE read delivering both packets — which is what the broker did.
        $connection->willRead(
            Packets::subAck(1, [0]) . Packets::publish('status/app', '{"state":"up"}', retain: true),
        );

        $received = [];

        $client->subscribe('status/app', static function (MqttMessage $m) use (&$received): void {
            $received[] = [$m->topic, $m->payload, $m->retained];
        });

        self::assertSame(
            [['status/app', '{"state":"up"}', true]],
            $received,
            'the retained message arrived in the same segment as the SUBACK and must not be dropped',
        );
    }

    /** And a refused subscription must still leave no entry behind. */
    public function test_a_refused_subscription_leaves_no_recorded_entry(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0x87]));

        try {
            $client->subscribe('secret/#', static fn () => null);
            self::fail('expected a refusal');
        } catch (MqttException) {
            // expected
        }

        self::assertSame(
            [],
            $client->subscribedFilters(),
            'recording early must not survive a refusal, or a reconnect would replay it',
        );
    }

    /** A partially refused batch keeps exactly the filters that were granted. */
    public function test_a_partially_refused_batch_keeps_only_the_granted_filters(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0x00, 0x87, 0x00]));

        try {
            $client->subscribeWith(
                [
                    new \Plugins\Mqtt\Domain\Subscription('a/#'),
                    new \Plugins\Mqtt\Domain\Subscription('secret/#'),
                    new \Plugins\Mqtt\Domain\Subscription('b/#'),
                ],
                [static fn () => null, static fn () => null, static fn () => null],
            );
            self::fail('expected a refusal');
        } catch (MqttException) {
            // expected
        }

        self::assertSame(['a/#', 'b/#'], $client->subscribedFilters());
    }

    /**
     * BUG 2 — AN MQTT 3.1.1 UNSUBACK HAS NO PAYLOAD AT ALL.
     *
     * §3.11: "The UNSUBACK Packet has no payload", with a Remaining Length of
     * exactly 2. The decoder required at least one reason code — a 5.0 rule —
     * so unsubscribing on 3.1.1 threw "malformed packet" against a broker that
     * was behaving perfectly.
     */
    public function test_a_311_unsuback_with_no_payload_is_accepted(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0, v5: false)]);
        $client     = $this->client($connection, ProtocolVersion::V311);
        $client->connect();

        $connection->willRead(Packets::subAck(1, [0], v5: false));
        $client->subscribe('a/#', static fn () => null);

        // A bare UNSUBACK: type 11, remaining length 2, the packet identifier,
        // and nothing else. Exactly what a 3.1.1 broker sends.
        $connection->willRead(Packets::wrap(PacketType::UnsubAck, 0, Packets::uint16(2)));

        $unsubAck = $client->unsubscribe(['a/#']);

        self::assertTrue(
            $unsubAck->isFullyGranted(),
            'a 3.1.1 UNSUBACK carries no per-filter detail, so it is read as success',
        );
        self::assertSame([], $client->subscribedFilters());
    }

    /** A 5.0 UNSUBACK still requires one reason code per filter. */
    public function test_a_v5_unsuback_still_requires_its_reason_codes(): void
    {
        $connection = new ScriptedConnection([Packets::connAck(0)]);
        $client     = $this->client($connection);
        $client->connect();

        // A well-formed 5.0 UNSUBACK as far as the property block — packet
        // identifier, then an empty property block — but with no reason codes
        // after it, which 5.0 requires one of per filter.
        $connection->willRead(Packets::wrap(
            PacketType::UnsubAck,
            0,
            Packets::uint16(1) . "\x00",
        ));

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/no reason codes/');

        $client->unsubscribe(['a/#']);
    }

    /**
     * BUG 3 — A PUBLISH MAY CARRY SEVERAL SUBSCRIPTION IDENTIFIERS.
     *
     * §3.3.2.3.8: "Multiple Subscription Identifiers will be included if the
     * publication is the result of a match to more than one subscription."
     * That is how a broker sending ONE copy tells a client which of its
     * subscriptions matched.
     *
     * The duplicate-property check treated the second as a Protocol Error, so a
     * conforming broker's PUBLISH was rejected as malformed and the connection
     * closed — and only for clients with OVERLAPPING subscriptions, so no test
     * without two of them could have caught it.
     */
    public function test_a_publish_may_carry_several_subscription_identifiers(): void
    {
        $properties = \chr(Property::SubscriptionIdentifier->value) . VarInt::encode(7)
            . \chr(Property::SubscriptionIdentifier->value) . VarInt::encode(9);

        $message = (new Decoder(ProtocolVersion::V5))->publish(
            $this->frame(Packets::publish('a/b', 'x', properties: $properties)),
        );

        self::assertSame([7, 9], $message->properties()->subscriptionIdentifiers());

        // The single-value accessor keeps working, returning the first.
        self::assertSame(7, $message->properties()->int(Property::SubscriptionIdentifier));
    }

    /** But repeating it in a SUBSCRIBE is still a Protocol Error (§3.8.2.1.2). */
    public function test_a_repeated_subscription_identifier_in_a_subscribe_is_still_refused(): void
    {
        self::assertTrue(Property::SubscriptionIdentifier->isRepeatable(PacketType::Publish));
        self::assertFalse(Property::SubscriptionIdentifier->isRepeatable(PacketType::Subscribe));

        $properties = \chr(Property::SubscriptionIdentifier->value) . VarInt::encode(7)
            . \chr(Property::SubscriptionIdentifier->value) . VarInt::encode(9);

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/appears more than once/');

        // Decoded as a SUBSCRIBE's property block directly. The repetition is
        // only legal in a PUBLISH, so the same bytes in a SUBSCRIBE must be
        // refused — which is the whole point of making the rule take a packet
        // type rather than being flat.
        \Plugins\Mqtt\Domain\Properties::decode(
            new \Plugins\Mqtt\Domain\ByteReader(VarInt::encode(\strlen($properties)) . $properties),
            PacketType::Subscribe,
        );
    }

    /**
     * BUG 4 — A 3.1.1-ONLY BROKER ANSWERS A 5.0 CONNECT IN THE 3.1.1 SHAPE.
     *
     * A 5.0 CONNACK body is at least three bytes; a 3.1.1 one is exactly two.
     * Sent a CONNECT with protocol level 5, a 3.1.1 broker replies in the only
     * format it knows — usually with return code 1, "unacceptable protocol
     * version".
     *
     * The decoder reported "the CONNACK property block runs past the end of the
     * packet", which sends an operator looking for a corrupt stream when the
     * answer is one environment variable. Measured against nats-server.
     */
    public function test_a_311_shaped_connack_is_reported_as_a_version_mismatch(): void
    {
        $client = $this->client(new ScriptedConnection([
            // Exactly what nats-server sends: 0x20 0x02 0x00 0x01.
            Packets::connAck(1, v5: false),
        ]));

        try {
            $client->connect();
            self::fail('expected a version mismatch');
        } catch (MqttException $e) {
            self::assertStringContainsString('does not implement MQTT 5.0', $e->getMessage());
            self::assertStringContainsString('unacceptable protocol version', $e->getMessage());
            self::assertStringContainsString('MQTT_VERSION=3.1.1', $e->getMessage());
            self::assertStringNotContainsString(
                'runs past the end',
                $e->getMessage(),
                'the old, unhelpful message must not come back',
            );
        }
    }

    /**
     * BUG 5 — THE PING INTERVAL FLOOR REMOVED THE WHOLE MARGIN.
     *
     * The interval is 80% of the keep-alive precisely so the packet has time to
     * travel before the broker's 1.5x deadline. A floor of 1.0 made a
     * keep-alive of 1 second have an interval of 1.0 — no margin at all — and a
     * real broker dropped every such connection before a PINGREQ went out.
     */
    public function test_a_one_second_keep_alive_still_leaves_a_ping_margin(): void
    {
        $options = ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            keepAlive: 1,
        );

        self::assertSame(0.8, $options->pingInterval());
        self::assertLessThan(1.0, $options->pingInterval(), 'there must be margin inside the window');

        // And the margin must be inside the broker's own 1.5x patience with
        // room to spare.
        self::assertLessThan(1.5, $options->pingInterval());
    }

    /** The ping really goes out inside a one-second window. */
    public function test_a_ping_goes_out_within_a_one_second_keep_alive(): void
    {
        $now        = 1000.0;
        $connection = new ScriptedConnection([Packets::connAck(0)]);

        $client = new MqttClient(
            $connection,
            ClientOptions::create(
                addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
                clientId: ClientId::generate(),
                keepAlive: 1,
                readTimeout: 0.05,
            ),
            null,
            static function () use (&$now): float {
                $now += 0.001;

                return $now;
            },
        );

        $client->connect();
        $connection->clearWritten();

        // 0.9 seconds: past the 0.8s interval and inside the broker's 1.5s.
        $now += 0.9;
        $client->run(0.01);

        self::assertStringContainsString("\xC0\x00", $connection->written, 'the PINGREQ went out in time');
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private function frame(string $bytes): RawPacket
    {
        $reader = new PacketReader();
        $reader->append($bytes);

        $packet = $reader->next();

        self::assertNotNull($packet);

        return $packet;
    }

    private function client(
        ScriptedConnection $connection,
        ProtocolVersion $version = ProtocolVersion::V5,
    ): MqttClient {
        $now = 1000.0;

        return new MqttClient(
            $connection,
            ClientOptions::create(
                addresses: [ServerAddress::parse('mqtt://127.0.0.1:1883')],
                clientId: ClientId::generate(),
                version: $version,
                connectTimeout: 0.2,
                readTimeout: 0.05,
                defaultQos: QoS::AtMostOnce,
            ),
            null,
            static function () use (&$now): float {
                $now += 0.01;

                return $now;
            },
        );
    }
}
