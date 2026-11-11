<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * Reads the fields of a framed packet.
 *
 * WHY THERE IS A METHOD PER PACKET TYPE RATHER THAN ONE `decode()`
 * ----------------------------------------------------------------
 * Because the client always knows what it is waiting for, and encoding that
 * knowledge is worth more than the convenience of a single entry point. Having
 * sent a CONNECT, the next packet must be a CONNACK; `[MQTT-3.2.0-1]` makes it
 * the broker's first packet, and anything else means the peer is not following
 * the protocol — a fact best discovered at the point of expectation rather than
 * three layers later when a field turns out to be missing.
 *
 * A single polymorphic `decode()` would have to return a union, and every
 * caller would then re-establish by hand what it already knew.
 *
 * EVERY METHOD ASSERTS THE PACKET IS FULLY CONSUMED
 * -------------------------------------------------
 * {@see ByteReader::assertConsumed()} is called at the end of each. A packet
 * with bytes left over has fields this client did not account for, and
 * accepting it would mean acting on a packet only partly understood — which for
 * a CONNACK means ignoring a limit the broker just imposed, and for a PUBLISH
 * means handing an application a payload that is not the whole payload.
 *
 * The exception is PUBLISH, whose payload deliberately runs to the end of the
 * packet, so there is nothing left over by construction.
 */
final readonly class Decoder
{
    public function __construct(public ProtocolVersion $version) {}

    /**
     * CONNACK.
     *
     * @throws MqttException when malformed, or when `sessionPresent` is set on
     *         a refusal — `[MQTT-3.2.2-6]` forbids that combination, and it
     *         matters because a client acting on it would resume a session the
     *         broker just declined to give it
     */
    public function connAck(RawPacket $packet): ConnAck
    {
        $this->assertType($packet, PacketType::ConnAck);

        $reader = $packet->reader();
        $ackFlags = $reader->uint8('the CONNACK acknowledge flags');

        if (($ackFlags & 0b1111_1110) !== 0) {
            // [MQTT-3.2.2-1] reserves bits 7-1. A non-zero one means this is
            // not a CONNACK as this version defines it.
            throw MqttException::malformedPacket(
                'the CONNACK acknowledge flags byte is 0b' . str_pad(decbin($ackFlags), 8, '0', \STR_PAD_LEFT)
                . ', but [MQTT-3.2.2-1] reserves every bit except bit 0 (Session Present) and requires '
                . 'them to be 0',
            );
        }

        $sessionPresent = ($ackFlags & 1) === 1;
        $raw            = $reader->uint8('the CONNACK reason code');

        if ($this->version->hasProperties()) {
            // A 5.0 CONNACK body is at least THREE bytes: the acknowledge
            // flags, the reason code, and a property block length of at least
            // one byte. Exactly two means the peer answered in the 3.1.1 shape,
            // which has no property block at all.
            //
            // This is what a 3.1.1-only broker does when sent a CONNECT with
            // protocol level 5: it replies in the only format it knows, usually
            // with return code 1, "unacceptable protocol version". Measured
            // against nats-server, which implements MQTT 3.1.1 and not 5.0.
            //
            // Reported as a version mismatch rather than as a malformed packet,
            // because it IS one and because "the CONNACK property block runs
            // past the end of the packet" sends an operator looking for a
            // corrupt stream when the answer is one environment variable.
            if ($reader->isExhausted()) {
                $asV311 = ReasonCode::fromV311ConnAck($raw);

                throw MqttException::handshakeFailed(
                    'this client asked for MQTT 5.0, and the broker answered with a 3.1.1-shaped '
                    . 'CONNACK — two bytes, with no property block, which a 5.0 CONNACK always has. '
                    . 'So this broker does not implement MQTT 5.0.'
                    . ($raw === 1
                        ? ' Its return code 1 says so in as many words: "unacceptable protocol '
                          . 'version".'
                        : ' Read as a 3.1.1 return code, the byte is ' . $raw
                          . ($asV311 !== null ? ' (' . $asV311->label() . ')' : '') . '.')
                    . ' Set MQTT_VERSION=3.1.1.',
                );
            }

            $reasonCode = ReasonCode::tryFrom($raw);

            if ($reasonCode === null) {
                throw MqttException::malformedPacket(
                    'the CONNACK carried reason code 0x'
                    . strtoupper(str_pad(dechex($raw), 2, '0', \STR_PAD_LEFT))
                    . ', which is not in the MQTT 5.0 reason code table',
                );
            }

            $properties = Properties::decode($reader, PacketType::ConnAck);
        } else {
            // 3.1.1: a "return code" from its own five-value table, and no
            // properties at all. Mapped onto the 5.0 table so the rest of this
            // client has one vocabulary.
            $reasonCode = ReasonCode::fromV311ConnAck($raw);

            if ($reasonCode === null) {
                throw MqttException::malformedPacket(
                    'the CONNACK carried return code ' . $raw . ', but MQTT 3.1.1 defines only 0-5 and '
                    . 'reserves 6-255. A broker sending this is not following the specification, and '
                    . 'inventing a meaning for it would be guessing at why the connection failed',
                );
            }

            $properties = Properties::none();
        }

        if ($sessionPresent && $reasonCode->isError()) {
            throw MqttException::malformedPacket(
                'the CONNACK refused the connection (' . $reasonCode->describe(PacketType::ConnAck)
                . ') but set Session Present, which [MQTT-3.2.2-6] forbids',
            );
        }

        $reader->assertConsumed('the CONNACK');

        return new ConnAck($sessionPresent, $reasonCode, $properties);
    }

    /**
     * PUBLISH — an application message.
     *
     * @throws MqttException when malformed
     */
    public function publish(RawPacket $packet): MqttMessage
    {
        $this->assertType($packet, PacketType::Publish);

        $qos = QoS::tryFromBits($packet->flags >> 1);

        if ($qos === null) {
            // Unreachable through PacketReader, which rejects QoS 3 in the
            // framing. Kept because this method is also reachable directly
            // from a test or a future caller, and the consequence of a missing
            // check is reading the payload at the wrong offset.
            throw MqttException::malformedPacket(
                'the PUBLISH has both QoS bits set; QoS 3 does not exist and a receiver must treat it '
                . 'as a Malformed Packet',
            );
        }

        $dup      = ($packet->flags & 0b1000) !== 0;
        $retained = ($packet->flags & 0b0001) !== 0;

        if ($dup && $qos === QoS::AtMostOnce) {
            throw MqttException::malformedPacket(
                'the PUBLISH is QoS 0 with the DUP flag set, and "the DUP flag MUST be set to 0 for '
                . 'all QoS 0 messages" — there is no acknowledgement at QoS 0, so there is no '
                . 're-delivery for it to describe',
            );
        }

        $reader = $packet->reader();
        $topic  = $reader->utf8('the PUBLISH topic');

        // The topic came from the broker, so it is checked as a NAME: a
        // wildcard here would mean the broker sent something [MQTT-3.3.2-2]
        // forbids, and an application matching it against its own filters would
        // get nonsense.
        $reason = Topic::reasonNameInvalid($topic);

        if ($reason !== '' && $topic !== '') {
            throw MqttException::malformedPacket(
                'the PUBLISH topic [' . MqttException::printable($topic) . '] is not a valid topic '
                . 'name: ' . $reason,
            );
        }

        $packetId = null;

        if ($qos->needsPacketId()) {
            $packetId = $reader->uint16('the PUBLISH packet identifier');

            if ($packetId === 0) {
                throw MqttException::malformedPacket(
                    'the PUBLISH at ' . $qos->label() . ' carried packet identifier 0, and an '
                    . 'identifier must be non-zero',
                );
            }
        }

        $properties = $this->version->hasProperties()
            ? Properties::decode($reader, PacketType::Publish)
            : Properties::none();

        if ($topic === '') {
            // A zero-length topic is legal ONLY with a Topic Alias, which
            // resolves it against an alias this client established. This client
            // never sends a Topic Alias Maximum, so a broker must not use one —
            // and a zero-length topic with no alias is unresolvable.
            $alias = $properties->int(Property::TopicAlias);

            throw MqttException::malformedPacket(
                'the PUBLISH carried an empty topic name'
                . ($alias !== null
                    ? ' and Topic Alias ' . $alias . '. This client does not advertise a Topic Alias '
                      . 'Maximum, so the broker must not use aliases, and there is no mapping to '
                      . 'resolve this against'
                    : ' and no Topic Alias, so there is nothing to resolve it against'),
            );
        }

        // No assertConsumed: the payload is the rest of the packet by
        // definition, so there is nothing left over.
        return new MqttMessage(
            topic: $topic,
            payload: $reader->rest(),
            qos: $qos,
            retained: $retained,
            dup: $dup,
            packetId: $packetId,
            properties: $properties,
        );
    }

    /**
     * PUBACK, PUBREC, PUBREL or PUBCOMP.
     *
     * @throws MqttException when malformed
     */
    public function ack(RawPacket $packet): Ack
    {
        if (!\in_array($packet->type, [
            PacketType::PubAck, PacketType::PubRec, PacketType::PubRel, PacketType::PubComp,
        ], true)) {
            throw MqttException::malformedPacket(
                'expected a publish acknowledgement and got ' . $packet->type->label(),
            );
        }

        $reader   = $packet->reader();
        $packetId = $reader->uint16('the ' . $packet->type->label() . ' packet identifier');

        if ($packetId === 0) {
            throw MqttException::malformedPacket(
                'the ' . $packet->type->label() . ' carried packet identifier 0, and an identifier '
                . 'must be non-zero',
            );
        }

        $reasonCode = ReasonCode::Success;
        $properties = Properties::none();

        // Both trailing fields are optional, in BOTH versions: a 3.1.1
        // acknowledgement has neither, and a 5.0 one omits them when the reason
        // is success with nothing to add. So their absence is the common case,
        // not an error.
        if ($this->version->hasProperties() && !$reader->isExhausted()) {
            $raw        = $reader->uint8('the ' . $packet->type->label() . ' reason code');
            $resolved   = ReasonCode::tryFrom($raw);

            if ($resolved === null) {
                throw MqttException::malformedPacket(
                    'the ' . $packet->type->label() . ' carried reason code 0x'
                    . strtoupper(str_pad(dechex($raw), 2, '0', \STR_PAD_LEFT))
                    . ', which is not in the MQTT 5.0 reason code table',
                );
            }

            $reasonCode = $resolved;

            // The property length itself is optional when the reason code is
            // the last byte — a three-byte 5.0 PUBACK is legal.
            if (!$reader->isExhausted()) {
                $properties = Properties::decode($reader, $packet->type);
            }
        }

        $reader->assertConsumed('the ' . $packet->type->label());

        return new Ack($packet->type, $packetId, $reasonCode, $properties);
    }

    /**
     * SUBACK or UNSUBACK.
     *
     * @param  list<string> $filters what was requested, in order, so a refusal
     *         can name the filter that caused it — the reply carries only bytes
     * @throws MqttException when malformed, or when the number of reason codes
     *         does not match the number of filters requested
     */
    public function subAck(RawPacket $packet, array $filters = []): SubAck
    {
        if ($packet->type !== PacketType::SubAck && $packet->type !== PacketType::UnsubAck) {
            throw MqttException::malformedPacket(
                'expected a SUBACK or UNSUBACK and got ' . $packet->type->label(),
            );
        }

        $reader   = $packet->reader();
        $packetId = $reader->uint16('the ' . $packet->type->label() . ' packet identifier');

        $properties = $this->version->hasProperties()
            ? Properties::decode($reader, $packet->type)
            : Properties::none();

        $codes = [];

        while (!$reader->isExhausted()) {
            $raw = $reader->uint8('a ' . $packet->type->label() . ' reason code');

            // An unrecognised code is kept as an int rather than refused. It is
            // still positional information, and dropping it would shift every
            // code after it onto the wrong filter — turning one unknown result
            // into a wrong result for everything following.
            $codes[] = ReasonCode::tryFrom($raw) ?? $raw;
        }

        // An MQTT 3.1.1 UNSUBACK has NO PAYLOAD. §3.11: "The UNSUBACK Packet has
        // no payload", with a Remaining Length of exactly 2 — the packet
        // identifier IS the whole acknowledgement, and there is no per-filter
        // detail to be had.
        //
        // Requiring a reason code here breaks unsubscribing on 3.1.1 entirely,
        // which is how this was found: a real 3.1.1 broker answered correctly
        // and this client called it malformed. Reason codes per filter are a
        // 5.0 addition (§3.11.3), and a 3.1.1 SUBACK does carry them — so the
        // exemption is narrow, for UNSUBACK on 3.1.1 only.
        $expectsCodes = $packet->type === PacketType::SubAck || $this->version->hasProperties();

        if ($codes === [] && $expectsCodes) {
            throw MqttException::malformedPacket(
                'the ' . $packet->type->label() . ' carried no reason codes, and there must be one '
                . 'per filter in the request',
            );
        }

        if ($codes === []) {
            // The 3.1.1 UNSUBACK case. The caller, which knows the filters,
            // turns this into one Success per filter so every version presents
            // the same shape.
            return new SubAck($packet->type, $packetId, [], $properties, $filters);
        }

        if ($filters !== [] && \count($codes) !== \count($filters)) {
            // Unrecoverable in the specific sense that matters: the only thing
            // tying a code to a filter is its position, so a mismatch leaves no
            // way to know which filter each code belongs to. Truncating or
            // padding would produce a confident wrong answer about which
            // subscriptions exist.
            throw MqttException::malformedPacket(
                'the ' . $packet->type->label() . ' carried ' . \count($codes) . ' reason code(s) for '
                . \count($filters) . ' requested filter(s). The reply names no filters — position is '
                . 'the only thing pairing them — so a mismatch makes every result unattributable',
            );
        }

        return new SubAck($packet->type, $packetId, $codes, $properties, $filters);
    }

    /** PINGRESP — asserts the shape and carries nothing. */
    public function pingResp(RawPacket $packet): void
    {
        $this->assertType($packet, PacketType::PingResp);

        // PacketReader already refused a non-zero Remaining Length on an empty
        // packet type, so there is nothing further to check.
    }

    /**
     * DISCONNECT sent by the broker — MQTT 5.0 only.
     *
     * @throws MqttException when malformed, or on 3.1.1, where a broker cannot
     *         send one at all
     */
    public function disconnect(RawPacket $packet): ServerDisconnect
    {
        $this->assertType($packet, PacketType::Disconnect);

        if (!$this->version->hasProperties()) {
            throw MqttException::malformedPacket(
                'the broker sent a DISCONNECT, which in MQTT 3.1.1 is a client-to-server packet only. '
                . 'A 3.1.1 broker ends a connection by closing the socket',
            );
        }

        $reader     = $packet->reader();
        $reasonCode = ReasonCode::Success;
        $properties = Properties::none();

        // A bare two-byte DISCONNECT means normal disconnection.
        if (!$reader->isExhausted()) {
            $raw      = $reader->uint8('the DISCONNECT reason code');
            $resolved = ReasonCode::tryFrom($raw);

            if ($resolved === null) {
                throw MqttException::malformedPacket(
                    'the DISCONNECT carried reason code 0x'
                    . strtoupper(str_pad(dechex($raw), 2, '0', \STR_PAD_LEFT))
                    . ', which is not in the MQTT 5.0 reason code table',
                );
            }

            $reasonCode = $resolved;

            if (!$reader->isExhausted()) {
                $properties = Properties::decode($reader, PacketType::Disconnect);
            }
        }

        $reader->assertConsumed('the DISCONNECT');

        return new ServerDisconnect($reasonCode, $properties);
    }

    /** @throws MqttException */
    private function assertType(RawPacket $packet, PacketType $expected): void
    {
        if ($packet->type === $expected) {
            return;
        }

        throw MqttException::malformedPacket(
            'expected ' . $expected->label() . ' and got ' . $packet->type->label()
            . ($packet->type->isClientOnly()
                ? ', which only a CLIENT sends — so the peer is either broken or is not a broker'
                : ''),
        );
    }
}
