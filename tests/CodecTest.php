<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\ByteReader;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Decoder;
use Plugins\Mqtt\Domain\Encoder;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\PacketReader;
use Plugins\Mqtt\Domain\PacketType;
use Plugins\Mqtt\Domain\Properties;
use Plugins\Mqtt\Domain\Property;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\RawPacket;
use Plugins\Mqtt\Domain\ReasonCode;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\Subscription;
use Plugins\Mqtt\Domain\Will;

/**
 * The packet codec, byte for byte.
 *
 * The encoder is asserted against bytes written out from the specification's
 * field order; the decoder is asserted against bytes built the same way in
 * {@see Packets}. They are deliberately NOT tested against each other: a codec
 * checked by round-tripping passes whenever its two halves agree, including
 * when both are wrong in the same way.
 */
final class CodecTest extends TestCase
{
    // ─── CONNECT ────────────────────────────────────────────────────────────

    /**
     * The whole variable header, byte by byte, against the specification's
     * Figure 3-2 onwards.
     */
    public function test_connect_variable_header_is_exactly_as_specified(): void
    {
        $packet = (new Encoder(ProtocolVersion::V5))->connect($this->options(clientId: 'abc'));

        // Fixed header: CONNECT is type 1, flags 0.
        self::assertSame(0x10, \ord($packet[0]));

        $body = substr($packet, 2);

        // Protocol Name: a two-byte length of 4, then "MQTT".
        self::assertSame("\x00\x04MQTT", substr($body, 0, 6));

        // Protocol Version: 5.
        self::assertSame(5, \ord($body[6]));

        // Connect Flags: Clean Start is bit 1, and bit 0 is reserved and must
        // be 0 [MQTT-3.1.2-3].
        self::assertSame(0b0000_0010, \ord($body[7]));
        self::assertSame(0, \ord($body[7]) & 1, 'bit 0 is reserved and MUST be 0');

        // Keep Alive: a Two Byte Integer, big-endian.
        self::assertSame("\x00\x3C", substr($body, 8, 2), '60 seconds');
    }

    public function test_connect_sets_the_flags_it_writes_a_payload_for(): void
    {
        $encoder = new Encoder(ProtocolVersion::V5);

        $withAuth = $encoder->connect($this->options(user: 'u', pass: 'p'));
        $flags    = \ord(substr($withAuth, 2)[7]);

        self::assertSame(0b1000_0000, $flags & 0b1000_0000, 'User Name Flag');
        self::assertSame(0b0100_0000, $flags & 0b0100_0000, 'Password Flag');

        $withWill = $encoder->connect($this->options(
            will: new Will('status', 'down', QoS::AtLeastOnce, retain: true),
        ));
        $willFlags = \ord(substr($withWill, 2)[7]);

        self::assertSame(0b0000_0100, $willFlags & 0b0000_0100, 'Will Flag');
        self::assertSame(1 << 3, $willFlags & 0b0001_1000, 'Will QoS 1 in bits 4-3');
        self::assertSame(0b0010_0000, $willFlags & 0b0010_0000, 'Will Retain');
    }

    /**
     * A password with no user name is legal in 5.0 and forbidden in 3.1.1, and
     * a configuration with one is far more likely to be a missing MQTT_USER
     * than a deliberate 5.0-only choice.
     */
    public function test_a_password_without_a_user_name_sets_neither_flag(): void
    {
        $packet = (new Encoder(ProtocolVersion::V5))->connect($this->options(user: '', pass: 'orphan'));
        $flags  = \ord(substr($packet, 2)[7]);

        self::assertSame(0, $flags & 0b1100_0000);
        self::assertStringNotContainsString('orphan', $packet);
    }

    /**
     * THE ONE-BYTE DIFFERENCE BETWEEN THE VERSIONS.
     *
     * A 5.0 CONNECT carries a property block; a 3.1.1 one has NO block at all,
     * not even a zero length. Emitting the `0x00` to a 3.1.1 broker shifts
     * every byte after it, so the broker reads the Client Identifier's length
     * from the wrong place and closes the connection as malformed — which looks
     * like a credential problem.
     */
    public function test_a_311_connect_carries_no_property_block_at_all(): void
    {
        $options = $this->options(clientId: 'abc', version: ProtocolVersion::V311);

        $v311 = (new Encoder(ProtocolVersion::V311))->connect($options);
        $body = substr($v311, 2);

        self::assertSame(4, \ord($body[6]), 'protocol level 4 for 3.1.1');

        // Byte 10 is the first byte after the Keep Alive. In 3.1.1 it is the
        // Client Identifier's length; in 5.0 it is the property block length.
        self::assertSame("\x00\x03abc", substr($body, 10), 'the client id follows the keep alive directly');

        $v5     = (new Encoder(ProtocolVersion::V5))->connect($this->options(clientId: 'abc'));
        $v5Body = substr($v5, 2);

        self::assertNotSame(
            "\x00\x03abc",
            substr($v5Body, 10, 5),
            '5.0 must have a property block here instead',
        );
        self::assertGreaterThan(\strlen($v311), \strlen($v5), '5.0 is longer by its property block');
    }

    /**
     * The will properties are a NESTED block inside the payload, and
     * `Will Delay Interval` belongs there and nowhere else. Putting it in
     * CONNECT's own property block is malformed — the easiest of these to get
     * wrong, because the two blocks sit a few bytes apart.
     */
    public function test_the_will_delay_interval_goes_in_the_will_properties(): void
    {
        $packet = (new Encoder(ProtocolVersion::V5))->connect($this->options(
            clientId: 'abc',
            will: new Will('status', 'down', delayInterval: 30),
        ));

        // 0x18 is Will Delay Interval; 30 as a Four Byte Integer.
        self::assertStringContainsString("\x18\x00\x00\x00\x1E", $packet);

        // It must appear AFTER the client id, which is where the payload — and
        // therefore the will block — begins.
        $idAt    = strpos($packet, "\x00\x03abc");
        $delayAt = strpos($packet, "\x18\x00\x00\x00\x1E");

        self::assertIsInt($idAt);
        self::assertIsInt($delayAt);
        self::assertGreaterThan($idAt, $delayAt, 'the will block is in the payload, after the client id');
    }

    public function test_putting_a_will_property_in_the_connect_block_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/Will Delay Interval belongs to the Will Properties/');

        Properties::of([Property::WillDelayInterval->value => 30])
            ->encode(PacketType::Connect, ProtocolVersion::V5);
    }

    /** The password is Binary Data, so a non-UTF-8 password must work. */
    public function test_a_password_may_contain_bytes_that_are_not_valid_utf8(): void
    {
        $binary = "\xFF\xFE\x00\x01";

        $packet = (new Encoder(ProtocolVersion::V5))->connect(
            $this->options(user: 'u', pass: $binary),
        );

        self::assertStringContainsString($binary, $packet, 'a password is Binary Data, not a string');
    }

    // ─── PUBLISH ────────────────────────────────────────────────────────────

    public function test_publish_fixed_header_flags(): void
    {
        $encoder = new Encoder(ProtocolVersion::V5);

        self::assertSame(0x30, \ord($encoder->publish('a', 'x')[0]), 'QoS 0, no retain, no dup');
        self::assertSame(0x31, \ord($encoder->publish('a', 'x', retain: true)[0]), 'retain is bit 0');
        self::assertSame(
            0x32,
            \ord($encoder->publish('a', 'x', QoS::AtLeastOnce, packetId: 1)[0]),
            'QoS in bits 2-1',
        );
        self::assertSame(
            0x34,
            \ord($encoder->publish('a', 'x', QoS::ExactlyOnce, packetId: 1)[0]),
            'QoS 2',
        );
        self::assertSame(
            0x3A,
            \ord($encoder->publish('a', 'x', QoS::AtLeastOnce, packetId: 1, dup: true)[0]),
            'dup is bit 3',
        );
    }

    /**
     * [MQTT-2.2.1-2]. Not pedantry: the two bytes sit between the topic and the
     * payload, so including them at QoS 0 makes the broker read the first two
     * payload bytes as an identifier and hand the application a payload short
     * by two.
     */
    public function test_a_qos0_publish_must_not_carry_a_packet_identifier(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT-2.2.1-2/');

        (new Encoder(ProtocolVersion::V5))->publish('a', 'x', QoS::AtMostOnce, packetId: 7);
    }

    public function test_a_qos1_publish_requires_a_packet_identifier(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/needs a packet identifier/');

        (new Encoder(ProtocolVersion::V5))->publish('a', 'x', QoS::AtLeastOnce);
    }

    public function test_a_zero_packet_identifier_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/zero is specifically not a valid identifier/');

        (new Encoder(ProtocolVersion::V5))->publish('a', 'x', QoS::AtLeastOnce, packetId: 0);
    }

    public function test_the_dup_flag_cannot_be_set_at_qos0(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/no acknowledgement, so there is no re-delivery/');

        (new Encoder(ProtocolVersion::V5))->publish('a', 'x', QoS::AtMostOnce, dup: true);
    }

    /**
     * An empty payload on a retained publish DELETES the retained message for
     * the topic. A real operation, not a degenerate case — so it must encode.
     */
    public function test_an_empty_retained_payload_encodes(): void
    {
        $packet = (new Encoder(ProtocolVersion::V5))->publish('a/b', '', retain: true);

        self::assertSame(0x31, \ord($packet[0]));

        $decoded = (new Decoder(ProtocolVersion::V5))->publish($this->frame($packet));

        self::assertSame('', $decoded->payload);
        self::assertTrue($decoded->retained);
    }

    public function test_publish_decodes_topic_flags_and_payload(): void
    {
        $bytes = Packets::publish('sensors/3/temp', '21.5', qos: 1, packetId: 42, retain: true);

        $message = (new Decoder(ProtocolVersion::V5))->publish($this->frame($bytes));

        self::assertSame('sensors/3/temp', $message->topic);
        self::assertSame('21.5', $message->payload);
        self::assertSame(QoS::AtLeastOnce, $message->qos);
        self::assertSame(42, $message->packetId);
        self::assertTrue($message->retained);
        self::assertFalse($message->dup);
    }

    /**
     * The payload runs to the end of the packet, with no length of its own —
     * which is correct ONLY because the reader is scoped to one packet. A
     * payload containing bytes that look like a fixed header must survive.
     */
    public function test_a_payload_containing_packet_like_bytes_survives(): void
    {
        $payload = "\x30\x05abc\xFF\x00";
        $bytes   = Packets::publish('a', $payload);

        $message = (new Decoder(ProtocolVersion::V5))->publish($this->frame($bytes));

        self::assertSame($payload, $message->payload);
    }

    /** A broker must not send a wildcard in a PUBLISH topic [MQTT-3.3.2-2]. */
    public function test_a_publish_from_the_broker_carrying_a_wildcard_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/not a valid topic name/');

        (new Decoder(ProtocolVersion::V5))->publish($this->frame(Packets::publish('a/#', 'x')));
    }

    /**
     * A zero-length topic is legal only with a Topic Alias. This client never
     * advertises a Topic Alias Maximum, so there is nothing to resolve it
     * against and the packet is unusable.
     */
    public function test_an_empty_topic_with_no_alias_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/empty topic name/');

        (new Decoder(ProtocolVersion::V5))->publish($this->frame(Packets::publish('', 'x')));
    }

    public function test_a_qos2_publish_with_a_zero_identifier_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/identifier 0/');

        (new Decoder(ProtocolVersion::V5))->publish(
            $this->frame(Packets::publish('a', 'x', qos: 2, packetId: 0)),
        );
    }

    // ─── SUBSCRIBE ──────────────────────────────────────────────────────────

    /**
     * SUBSCRIBE, UNSUBSCRIBE and PUBREL require fixed-header flags of `0b0010`,
     * not `0b0000`. It looks arbitrary and is easy to "tidy up" to zero — and a
     * SUBSCRIBE with `0b0000` is not answered with an error: the broker closes
     * the socket, which a client reads as a network failure and retries,
     * forever.
     */
    public function test_subscribe_unsubscribe_and_pubrel_require_flags_0010(): void
    {
        $encoder = new Encoder(ProtocolVersion::V5);

        self::assertSame(
            0x82,
            \ord($encoder->subscribe(1, [new Subscription('a')])[0]),
            'SUBSCRIBE is 0x80 | 0b0010',
        );
        self::assertSame(0xA2, \ord($encoder->unsubscribe(1, ['a'])[0]), 'UNSUBSCRIBE');
        self::assertSame(0x62, \ord($encoder->ack(PacketType::PubRel, 1)[0]), 'PUBREL');

        // And the others require zero.
        self::assertSame(0x40, \ord($encoder->ack(PacketType::PubAck, 1)[0]), 'PUBACK');
        self::assertSame(0x50, \ord($encoder->ack(PacketType::PubRec, 1)[0]), 'PUBREC');
        self::assertSame(0x70, \ord($encoder->ack(PacketType::PubComp, 1)[0]), 'PUBCOMP');
        self::assertSame(0xC0, \ord($encoder->pingReq()[0]), 'PINGREQ');
    }

    public function test_the_subscription_options_byte_per_version(): void
    {
        $subscription = new Subscription(
            filter: 'a/+',
            qos: QoS::AtLeastOnce,
            noLocal: true,
            retainAsPublished: true,
            retainHandling: Subscription::RETAIN_SEND_NEVER,
        );

        // 5.0: QoS 1 | No Local | Retain As Published | Retain Handling 2 << 4
        self::assertSame(
            0b0010_1101,
            $subscription->optionsByte(ProtocolVersion::V5),
        );

        // 3.1.1: the QoS alone. Every other bit is RESERVED, and a non-zero
        // reserved bit makes the whole SUBSCRIBE malformed — so the 5.0 options
        // must be dropped rather than carried.
        self::assertSame(1, $subscription->optionsByte(ProtocolVersion::V311));
    }

    public function test_an_empty_subscribe_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/at least one topic filter/');

        // Deliberately empty: the point is that the encoder refuses it rather
        // than emitting a SUBSCRIBE with no filters, which is a Protocol Error
        // the broker answers by closing the connection. Built at runtime so a
        // static analyser does not reject the test for testing the guard.
        /** @var non-empty-list<Subscription> $none */
        $none = array_filter([new Subscription('a')], static fn (): bool => false);

        (new Encoder(ProtocolVersion::V5))->subscribe(1, $none);
    }

    /** [MQTT-3.8.3-4]: No Local on a shared subscription is a Protocol Error. */
    public function test_no_local_on_a_shared_subscription_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT-3.8.3-4/');

        (new Subscription('$share/g/a', noLocal: true))->assertValid(ProtocolVersion::V5);
    }

    /**
     * A Subscription Identifier is used for ROUTING, so dropping it silently
     * on 3.1.1 would misroute messages — refused instead.
     */
    public function test_a_subscription_identifier_is_refused_on_311(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT 3.1.1 has no properties to carry it/');

        (new Subscription('a', subscriptionIdentifier: 7))->assertValid(ProtocolVersion::V311);
    }

    public function test_a_subscribe_batch_cannot_mix_subscription_identifiers(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/one Subscription Identifier for every filter/');

        $batch = [
            new Subscription('a', subscriptionIdentifier: 1),
            new Subscription('b', subscriptionIdentifier: 2),
        ];

        (new Encoder(ProtocolVersion::V5))->subscribe(1, $batch);
    }

    // ─── Acknowledgements ───────────────────────────────────────────────────

    /**
     * A 3.1.1 acknowledgement is the identifier and nothing else, and in 5.0
     * both trailing fields are optional — so a four-byte PUBACK is the common
     * form, not an error.
     */
    public function test_a_four_byte_puback_is_valid_in_both_versions(): void
    {
        foreach ([ProtocolVersion::V311, ProtocolVersion::V5] as $version) {
            $packet = (new Encoder($version))->ack(PacketType::PubAck, 7);

            self::assertSame(4, \strlen($packet), $version->label() . ' PUBACK is four bytes');

            $ack = (new Decoder($version))->ack($this->frame($packet));

            self::assertSame(7, $ack->packetId);
            self::assertSame(ReasonCode::Success, $ack->reasonCode);
        }
    }

    public function test_a_five_byte_v5_puback_carries_only_a_reason_code(): void
    {
        // The property length is optional when the reason code is the last byte.
        $bytes = Packets::ack(PacketType::PubAck, 7, reasonCode: 0x10);

        self::assertSame(5, \strlen($bytes));

        $ack = (new Decoder(ProtocolVersion::V5))->ack($this->frame($bytes));

        self::assertSame(ReasonCode::NoMatchingSubscribers, $ack->reasonCode);
        self::assertTrue($ack->reasonCode->isSilentNoOp(), 'accepted, and nobody was listening');
        self::assertFalse($ack->reasonCode->isError(), '0x10 is below the error boundary');
    }

    public function test_a_reason_code_is_only_written_when_it_says_something(): void
    {
        $encoder = new Encoder(ProtocolVersion::V5);

        self::assertSame(4, \strlen($encoder->ack(PacketType::PubAck, 7)), 'success and no properties');
        self::assertSame(
            5,
            \strlen($encoder->ack(PacketType::PubAck, 7, ReasonCode::NotAuthorized)),
            'a non-success reason is written',
        );
    }

    public function test_a_311_acknowledgement_never_carries_a_reason_code(): void
    {
        $packet = (new Encoder(ProtocolVersion::V311))
            ->ack(PacketType::PubAck, 7, ReasonCode::NotAuthorized);

        self::assertSame(4, \strlen($packet), '3.1.1 has nowhere to put a reason code');
    }

    // ─── CONNACK ────────────────────────────────────────────────────────────

    public function test_connack_decodes_session_present_and_the_reason_code(): void
    {
        $connAck = (new Decoder(ProtocolVersion::V5))
            ->connAck($this->frame(Packets::connAck(0, sessionPresent: true)));

        self::assertTrue($connAck->sessionPresent);
        self::assertTrue($connAck->isAccepted());
    }

    public function test_connack_decodes_the_brokers_limits(): void
    {
        $properties = Packets::byteProperty(Property::MaximumQoS->value, 1)
            . Packets::uint16Property(Property::ReceiveMaximum->value, 20)
            . Packets::uint32Property(Property::MaximumPacketSize->value, 65536)
            . Packets::byteProperty(Property::RetainAvailable->value, 0)
            . Packets::byteProperty(Property::SharedSubscriptionAvailable->value, 0)
            . Packets::uint16Property(Property::ServerKeepAlive->value, 30)
            . Packets::stringProperty(Property::AssignedClientIdentifier->value, 'broker-chose-this');

        $connAck = (new Decoder(ProtocolVersion::V5))
            ->connAck($this->frame(Packets::connAck(0, properties: $properties)));

        self::assertSame(QoS::AtLeastOnce, $connAck->maximumQoS());
        self::assertSame(20, $connAck->receiveMaximum());
        self::assertSame(65536, $connAck->maximumPacketSize());
        self::assertFalse($connAck->retainAvailable());
        self::assertFalse($connAck->sharedSubscriptionsAvailable());
        self::assertTrue($connAck->wildcardSubscriptionsAvailable(), 'absent means available');
        self::assertSame(30, $connAck->serverKeepAlive());
        self::assertSame('broker-chose-this', $connAck->assignedClientId());
    }

    /** Absent properties must default to the PERMISSIVE value, or 3.1.1 breaks. */
    public function test_absent_limits_default_to_permissive(): void
    {
        $connAck = (new Decoder(ProtocolVersion::V311))
            ->connAck($this->frame(Packets::connAck(0, v5: false)));

        self::assertSame(QoS::ExactlyOnce, $connAck->maximumQoS());
        self::assertSame(65535, $connAck->receiveMaximum());
        self::assertNull($connAck->maximumPacketSize());
        self::assertTrue($connAck->retainAvailable());
        self::assertTrue($connAck->wildcardSubscriptionsAvailable());
        self::assertTrue($connAck->sharedSubscriptionsAvailable());
        self::assertNull($connAck->serverKeepAlive());
    }

    /** The five 3.1.1 return codes map onto the 5.0 table. */
    public function test_the_311_return_codes_map_onto_the_v5_table(): void
    {
        $expected = [
            1 => ReasonCode::UnsupportedProtocolVersion,
            2 => ReasonCode::ClientIdentifierNotValid,
            3 => ReasonCode::ServerUnavailable,
            4 => ReasonCode::BadUserNameOrPassword,
            5 => ReasonCode::NotAuthorized,
        ];

        foreach ($expected as $code => $reason) {
            $connAck = (new Decoder(ProtocolVersion::V311))
                ->connAck($this->frame(Packets::connAck($code, v5: false)));

            self::assertSame($reason, $connAck->reasonCode, 'return code ' . $code);
            self::assertFalse($connAck->isAccepted());
        }
    }

    public function test_a_311_return_code_above_five_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/defines only 0-5/');

        (new Decoder(ProtocolVersion::V311))->connAck($this->frame(Packets::connAck(6, v5: false)));
    }

    /** [MQTT-3.2.2-1] reserves bits 7-1 of the acknowledge flags byte. */
    public function test_a_reserved_connack_flag_bit_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT-3.2.2-1/');

        (new Decoder(ProtocolVersion::V5))->connAck(
            $this->frame(Packets::wrap(PacketType::ConnAck, 0, "\x02\x00\x00")),
        );
    }

    /**
     * [MQTT-3.2.2-6]: a refusal must have Session Present clear. Acting on the
     * combination would mean resuming a session the broker just declined.
     */
    public function test_session_present_on_a_refusal_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT-3.2.2-6/');

        (new Decoder(ProtocolVersion::V5))
            ->connAck($this->frame(Packets::connAck(0x87, sessionPresent: true)));
    }

    // ─── Properties ─────────────────────────────────────────────────────────

    /**
     * The property block is TLV with no L: the identifier alone says how wide
     * the value is. So an unknown identifier cannot be skipped — there is no
     * way to know whether one byte follows or four.
     */
    public function test_an_unknown_property_identifier_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/is not an MQTT 5.0 property/');

        (new Decoder(ProtocolVersion::V5))->connAck(
            $this->frame(Packets::connAck(0, properties: "\x07\x01")),
        );
    }

    /** A packet carrying an identifier invalid for its type is malformed. */
    public function test_a_misplaced_property_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/is not valid in PUBLISH/');

        (new Decoder(ProtocolVersion::V5))->publish($this->frame(Packets::publish(
            'a',
            'x',
            properties: Packets::byteProperty(Property::MaximumQoS->value, 1),
        )));
    }

    /**
     * A duplicate is a Protocol Error for every property but User Property.
     * Enforced rather than resolved, because "keep the first" and "keep the
     * last" are both defensible — so two implementations will choose
     * differently, and a sender can use that to make them disagree.
     */
    public function test_a_duplicate_property_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/appears more than once/');

        (new Decoder(ProtocolVersion::V5))->connAck($this->frame(Packets::connAck(
            0,
            properties: Packets::uint16Property(Property::ReceiveMaximum->value, 10)
                . Packets::uint16Property(Property::ReceiveMaximum->value, 20),
        )));
    }

    /**
     * User Property is the ONE repeatable property, it is ordered, and names
     * may repeat — so it cannot be stored in an associative array.
     */
    public function test_user_properties_keep_their_order_and_duplicate_names(): void
    {
        $block = Packets::stringProperty(Property::UserProperty->value, 'a') . Packets::str('1')
            . Packets::stringProperty(Property::UserProperty->value, 'b') . Packets::str('2')
            . Packets::stringProperty(Property::UserProperty->value, 'a') . Packets::str('3');

        $message = (new Decoder(ProtocolVersion::V5))
            ->publish($this->frame(Packets::publish('t', 'p', properties: $block)));

        self::assertSame(
            [['a', '1'], ['b', '2'], ['a', '3']],
            $message->properties()->userProperties(),
        );
        self::assertSame('3', $message->properties()->userProperty('a'), 'the last wins for a lookup');
    }

    public function test_publish_properties_are_exposed_through_the_message(): void
    {
        $block = Packets::byteProperty(Property::PayloadFormatIndicator->value, 1)
            . Packets::stringProperty(Property::ContentType->value, 'application/json')
            . Packets::stringProperty(Property::ResponseTopic->value, 'replies/7')
            . \chr(Property::CorrelationData->value) . Packets::str('abc');

        $message = (new Decoder(ProtocolVersion::V5))
            ->publish($this->frame(Packets::publish('t', '{}', properties: $block)));

        self::assertTrue($message->declaresUtf8Payload());
        self::assertSame('application/json', $message->contentType());
        self::assertSame('replies/7', $message->responseTopic());
        self::assertSame('abc', $message->correlationData());
    }

    /** A property that lies about its length must not read past its block. */
    public function test_a_property_overrunning_its_block_is_refused(): void
    {
        $this->expectException(MqttException::class);

        // Declares a 2-byte block but puts a string property in it whose own
        // length points well beyond.
        (new Decoder(ProtocolVersion::V5))->connAck($this->frame(
            Packets::wrap(PacketType::ConnAck, 0, "\x00\x00" . "\x02" . "\x1F\xFF"),
        ));
    }

    // ─── Leftover bytes ─────────────────────────────────────────────────────

    /**
     * A packet with bytes left over has fields this client did not account for.
     * Accepting it would mean acting on a packet only partly understood.
     */
    public function test_trailing_bytes_in_a_connack_are_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/left over/');

        (new Decoder(ProtocolVersion::V5))->connAck(
            $this->frame(Packets::wrap(PacketType::ConnAck, 0, "\x00\x00\x00" . 'extra')),
        );
    }

    public function test_a_reader_reports_a_length_pointing_past_the_end(): void
    {
        // A two-byte length of 60000 inside a short packet. substr() would
        // return a short string and the decode would carry on at a wrong
        // offset; this must throw instead.
        $reader = new ByteReader("\xEA\x60short");

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/only \d+ remain/');

        $reader->utf8('a topic');
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    /** Frame a complete packet the way the reader would. */
    private function frame(string $bytes): RawPacket
    {
        $reader = new PacketReader();
        $reader->append($bytes);

        $packet = $reader->next();

        self::assertNotNull($packet, 'the test fixture must be a complete packet');

        return $packet;
    }

    private function options(
        string $clientId = 'test',
        string $user = '',
        string $pass = '',
        ProtocolVersion $version = ProtocolVersion::V5,
        ?Will $will = null,
    ): ClientOptions {
        return ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1:1883')],
            clientId: ClientId::configured($clientId),
            user: $user,
            pass: $pass,
            version: $version,
            will: $will,
        );
    }
}
