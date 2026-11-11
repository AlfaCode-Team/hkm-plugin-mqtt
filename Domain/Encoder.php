<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * The only thing that formats an MQTT packet.
 *
 * ONE GATE IN FRONT OF ONE ENCODER
 * --------------------------------
 * Every topic goes through {@see Topic}, every string through {@see Utf8},
 * every property through {@see Properties}, and every fixed header through
 * {@see PacketType::isFlagsValid()} — and they do so because this class is the
 * single place a packet is built. The same arrangement as the NATS plugin's
 * `Protocol`, for the same reason: validation that can be bypassed is
 * validation that will be.
 *
 * WHY THE VERSION IS A CONSTRUCTOR ARGUMENT
 * -----------------------------------------
 * Because the difference between 3.1.1 and 5.0 is not a flag the caller should
 * have to remember at each call. It is a property-block byte that must be
 * present in every 5.0 packet and ABSENT — not zero — in every 3.1.1 one, and a
 * caller that forgot it on one packet type would produce a connection that
 * handshakes and then fails on the first publish.
 *
 * So the version is fixed once, here, and every method consults it.
 *
 * THE CONNECT PAYLOAD'S ORDER IS NOT NEGOTIABLE
 * ---------------------------------------------
 * Client Identifier, Will Properties, Will Topic, Will Payload, User Name,
 * Password — in that order, each present only if the corresponding Connect
 * Flag is set. There is no length prefix around the group and no field names,
 * so the flags and the payload have to agree exactly: a Password Flag set with
 * no password written leaves the broker reading the next packet's bytes as a
 * password length.
 *
 * That coupling is why {@see self::connect()} computes the flags from the same
 * values it then writes, in one pass, instead of taking a flag byte.
 */
final readonly class Encoder
{
    public function __construct(public ProtocolVersion $version) {}

    /**
     * CONNECT — the first packet, and the only one that carries credentials.
     *
     * @throws MqttException when any field could not go on the wire
     */
    public function connect(ClientOptions $options): string
    {
        $out = new ByteWriter();

        // ── Variable header ────────────────────────────────────────────────
        $out->utf8($this->version->protocolName(), 'the protocol name')
            ->uint8($this->version->value);

        $will = $options->will;

        // The flags describe the payload that follows, so they are computed
        // from exactly the values written below. Bit 0 is reserved and MUST be
        // 0 [MQTT-3.1.2-3].
        $flags = 0;

        if ($options->cleanStart) {
            $flags |= 0b0000_0010;
        }

        if ($will !== null) {
            $flags |= 0b0000_0100;
            $flags |= ($will->qos->value & 0b11) << 3;

            if ($will->retain) {
                $flags |= 0b0010_0000;
            }
        }

        if ($options->user !== '') {
            $flags |= 0b1000_0000;

            // A password with no user name is legal in 5.0 and NOT in 3.1.1,
            // where [MQTT-3.1.2-22] forbids it. Rather than encode a form one
            // version rejects, the password is tied to the user name here — and
            // a configuration with a password and no user is far more likely to
            // be a missing MQTT_USER than a deliberate 5.0-only choice.
            if ($options->pass !== '') {
                $flags |= 0b0100_0000;
            }
        }

        $out->uint8($flags)->uint16($options->keepAlive);

        // ── CONNECT properties (5.0 only) ──────────────────────────────────
        $out->raw(Properties::of([
            // Only sent when non-zero: a Session Expiry Interval of 0 is the
            // protocol's default and means "end the session when the connection
            // ends", so writing it explicitly adds five bytes to every
            // handshake to say what silence already says.
            Property::SessionExpiryInterval->value => $options->sessionExpiry > 0
                ? $options->sessionExpiry
                : null,

            // Ask the broker to include a Reason String and User Properties on
            // failures. Costs two bytes and is the difference between
            // "0x87 Not authorized" and a broker explaining which ACL refused.
            Property::RequestProblemInformation->value => 1,
        ])->encode(PacketType::Connect, $this->version));

        // ── Payload, in the one order the protocol allows ──────────────────
        $out->utf8($options->clientId->value, 'the Client Identifier');

        if ($will !== null) {
            // The Will Properties are a nested block INSIDE the payload, with
            // their own length. They are not CONNECT's properties, and a
            // property legal in one is not necessarily legal in the other —
            // Will Delay Interval belongs here and nowhere else.
            $out->raw($will->properties($this->version)->encode(PacketType::Connect, $this->version, will: true));

            Topic::assertName($will->topic);

            $out->utf8($will->topic, 'the will topic')
                ->binary($will->payload, 'the will payload');
        }

        if ($options->user !== '') {
            $out->utf8($options->user, 'the user name');

            if ($options->pass !== '') {
                // Binary Data, not a string: [3.1.3.6] makes the password
                // Binary Data precisely so a password may contain bytes that
                // are not valid UTF-8. Encoding it as a string would refuse
                // perfectly good passwords.
                $out->binary($options->pass, 'the password');
            }
        }

        return $out->asPacket(PacketType::Connect);
    }

    /**
     * PUBLISH.
     *
     * @param  ?int $packetId required at QoS 1 and 2, forbidden at QoS 0
     * @throws MqttException when the topic, payload or identifier is unusable
     */
    public function publish(
        string $topic,
        string $payload,
        QoS $qos = QoS::AtMostOnce,
        bool $retain = false,
        ?int $packetId = null,
        ?Properties $properties = null,
        bool $dup = false,
    ): string {
        Topic::assertName($topic);

        if ($qos->needsPacketId() && $packetId === null) {
            throw MqttException::cannotEncode(
                'a PUBLISH at ' . $qos->label() . ' needs a packet identifier so its acknowledgement '
                . 'can be matched, and none was supplied',
            );
        }

        if (!$qos->needsPacketId() && $packetId !== null) {
            // [MQTT-2.2.1-2]. Not pedantry: the two bytes sit between the topic
            // and the payload, so including them at QoS 0 makes the broker read
            // the first two payload bytes as an identifier and hand the
            // application a payload short by two.
            throw MqttException::cannotEncode(
                'a PUBLISH at QoS 0 must not carry a packet identifier [MQTT-2.2.1-2], and '
                . $packetId . ' was supplied. The two bytes would sit between the topic and the '
                . 'payload, so the broker would read the payload shifted by two',
            );
        }

        if ($packetId !== null && ($packetId < PacketIds::MIN || $packetId > PacketIds::MAX)) {
            throw MqttException::cannotEncode(
                'a packet identifier must be between ' . PacketIds::MIN . ' and ' . PacketIds::MAX
                . ', and ' . $packetId . ' was supplied'
                . ($packetId === 0 ? ' — zero is specifically not a valid identifier' : ''),
            );
        }

        if ($dup && $qos === QoS::AtMostOnce) {
            // "The DUP flag MUST be set to 0 for all QoS 0 messages." There is
            // nothing to re-deliver at QoS 0, so a DUP there is meaningless.
            throw MqttException::cannotEncode(
                'the DUP flag cannot be set on a QoS 0 PUBLISH: there is no acknowledgement, so there '
                . 'is no re-delivery for it to describe',
            );
        }

        $out = new ByteWriter();
        $out->utf8($topic, 'the PUBLISH topic');

        if ($packetId !== null) {
            $out->uint16($packetId);
        }

        $out->raw(($properties ?? Properties::none())->encode(PacketType::Publish, $this->version));

        // No length prefix: the payload runs to the end of the packet, which
        // the Remaining Length already bounds. This is also why a PUBLISH
        // payload may be empty — and an empty payload on a retained publish is
        // how a retained message is DELETED, which is a real operation rather
        // than a degenerate case.
        $out->raw($payload);

        $flags = ($qos->value & 0b11) << 1;

        if ($retain) {
            $flags |= 0b0001;
        }

        if ($dup) {
            $flags |= 0b1000;
        }

        return $out->asPacket(PacketType::Publish, $flags);
    }

    /**
     * SUBSCRIBE.
     *
     * @param  non-empty-list<Subscription> $subscriptions
     * @throws MqttException when the list is empty or any filter is unusable
     */
    public function subscribe(int $packetId, array $subscriptions): string
    {
        if ($subscriptions === []) {
            // "The Payload MUST contain at least one Topic Filter and
            // Subscription Options pair." A SUBSCRIBE with no filters is a
            // Protocol Error, and the broker's answer is to close the
            // connection — so an empty loop here would cost the whole session.
            throw MqttException::cannotEncode(
                'a SUBSCRIBE must carry at least one topic filter; an empty one is a Protocol Error '
                . 'and the broker answers it by closing the connection',
            );
        }

        $out = new ByteWriter();
        $out->uint16($this->assertPacketId($packetId));

        // The Subscription Identifier is a SUBSCRIBE-level property, not a
        // per-filter one, so a list whose members disagree about it cannot be
        // encoded in one packet.
        $identifiers = [];

        foreach ($subscriptions as $subscription) {
            if ($subscription->subscriptionIdentifier !== null) {
                $identifiers[$subscription->subscriptionIdentifier] = true;
            }
        }

        if (\count($identifiers) > 1) {
            throw MqttException::cannotEncode(
                'a SUBSCRIBE carries one Subscription Identifier for every filter in it, and this '
                . 'batch asks for ' . \count($identifiers) . ' different ones. Send them as separate '
                . 'SUBSCRIBE packets',
            );
        }

        $out->raw(Properties::of([
            Property::SubscriptionIdentifier->value => $identifiers === []
                ? null
                : array_key_first($identifiers),
        ])->encode(PacketType::Subscribe, $this->version));

        foreach ($subscriptions as $subscription) {
            $subscription->assertValid($this->version);

            $out->utf8($subscription->filter, 'a subscription filter')
                ->uint8($subscription->optionsByte($this->version));
        }

        // 0b0010 is required, not decorative — see PacketType::reservedFlags().
        return $out->asPacket(PacketType::Subscribe, 0b0010);
    }

    /**
     * UNSUBSCRIBE.
     *
     * @param  non-empty-list<string> $filters compared character by character
     *         by the broker [MQTT-3.10.4-1], so they must be spelled exactly as
     *         they were subscribed
     * @throws MqttException when the list is empty or any filter is unusable
     */
    public function unsubscribe(int $packetId, array $filters): string
    {
        if ($filters === []) {
            throw MqttException::cannotEncode(
                'an UNSUBSCRIBE must carry at least one topic filter; an empty one is a Protocol Error',
            );
        }

        $out = new ByteWriter();
        $out->uint16($this->assertPacketId($packetId))
            ->raw(Properties::none()->encode(PacketType::Unsubscribe, $this->version));

        foreach ($filters as $filter) {
            Topic::assertFilter($filter);

            $out->utf8($filter, 'an unsubscribe filter');
        }

        return $out->asPacket(PacketType::Unsubscribe, 0b0010);
    }

    /** PUBACK, PUBREC, PUBREL or PUBCOMP. */
    public function ack(
        PacketType $type,
        int $packetId,
        ReasonCode $reasonCode = ReasonCode::Success,
        ?Properties $properties = null,
    ): string {
        if (!\in_array($type, [
            PacketType::PubAck, PacketType::PubRec, PacketType::PubRel, PacketType::PubComp,
        ], true)) {
            throw MqttException::cannotEncode(
                $type->label() . ' is not one of the four single-identifier acknowledgements',
            );
        }

        $out = new ByteWriter();
        $out->uint16($this->assertPacketId($packetId));

        $extra = $properties ?? Properties::none();

        // A 3.1.1 acknowledgement is the identifier and nothing else, and in
        // 5.0 BOTH trailing fields are independently optional:
        //
        //   "The Reason Code and Property Length can be omitted if the Reason
        //    Code is 0x00 (Success) and there are no Properties."
        //   "If the Remaining Length is less than 4 there is no Property Length
        //    and the value of 0 is used."
        //
        // So the two omissions are separate. Writing the reason code does NOT
        // oblige writing an empty property block after it — and omitting that
        // byte is what keeps a plain success at four bytes and a bare refusal
        // at five, rather than six. On a QoS 1 subscriber that is a byte per
        // message, and it is the shortest form every broker must accept.
        if ($this->version->hasProperties()) {
            if (!$extra->isEmpty()) {
                $out->uint8($reasonCode->value)
                    ->raw($extra->encode($type, $this->version));
            } elseif ($reasonCode !== ReasonCode::Success) {
                $out->uint8($reasonCode->value);
            }
        }

        // PUBREL requires 0b0010; the other three require 0b0000.
        return $out->asPacket($type, $type->reservedFlags() ?? 0);
    }

    /** PINGREQ — two bytes, and the only thing keeping an idle subscription alive. */
    public function pingReq(): string
    {
        return (new ByteWriter())->asPacket(PacketType::PingReq);
    }

    /**
     * DISCONNECT.
     *
     * The reason code matters more than it looks. A plain DISCONNECT tells the
     * broker this was a clean exit, and the broker then DISCARDS the will — so
     * a process with a "down" will that shuts down politely publishes no
     * "down". `0x04 Disconnect with Will Message` is how to exit cleanly AND
     * fire the will, and it exists for exactly that.
     *
     * On 3.1.1 there is no reason code at all: DISCONNECT is two bytes and the
     * will is always discarded.
     */
    public function disconnect(
        ReasonCode $reasonCode = ReasonCode::Success,
        ?Properties $properties = null,
    ): string {
        $out   = new ByteWriter();
        $extra = $properties ?? Properties::none();

        // The same two independent omissions as an acknowledgement:
        //
        //   "The Reason Code and Property Length can be omitted if the Reason
        //    Code is 0x00 (Normal disconnection) and there are no Properties."
        //   "If the Remaining Length is less than 2, a value of 0 is used."
        if ($this->version->hasProperties()) {
            if (!$extra->isEmpty()) {
                $out->uint8($reasonCode->value)
                    ->raw($extra->encode(PacketType::Disconnect, $this->version));
            } elseif ($reasonCode !== ReasonCode::Success) {
                $out->uint8($reasonCode->value);
            }
        }

        return $out->asPacket(PacketType::Disconnect);
    }

    /** @throws MqttException */
    private function assertPacketId(int $packetId): int
    {
        if ($packetId < PacketIds::MIN || $packetId > PacketIds::MAX) {
            throw MqttException::cannotEncode(
                'a packet identifier must be between ' . PacketIds::MIN . ' and ' . PacketIds::MAX
                . ', and ' . $packetId . ' was supplied'
                . ($packetId === 0 ? ' — zero is specifically not a valid identifier' : ''),
            );
        }

        return $packetId;
    }
}
