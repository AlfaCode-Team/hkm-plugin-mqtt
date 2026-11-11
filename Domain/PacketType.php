<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * The fifteen MQTT Control Packet types, and the flags each one's header must carry.
 *
 * THE LOW NIBBLE IS NOT FREE SPACE
 * --------------------------------
 * Byte 1 of every MQTT packet is `type << 4 | flags`. For PUBLISH the four
 * flag bits are real — DUP, QoS, RETAIN — but for ten of the other fourteen
 * types they are RESERVED with an exact required value, and the specification
 * is blunt about what a receiver does with anything else: SUBSCRIBE, UNSUBSCRIBE
 * and PUBREL must be `0b0010`, everything else reserved must be `0b0000`, and a
 * violation is a Malformed Packet, which closes the connection.
 *
 * Those three being `0010` rather than `0000` is the detail that bites. It
 * looks arbitrary, it is easy to "tidy up" to zero, and a SUBSCRIBE sent with
 * `0b0000` is not answered with an error — the broker closes the socket, which
 * a client reads as a network failure and retries, forever.
 *
 * So the required value lives next to the type, in {@see self::reservedFlags()},
 * and {@see self::isFlagsValid()} is applied to every packet in both
 * directions. Encoding one correctly and then failing to VERIFY an inbound one
 * is the easier half done twice.
 */
enum PacketType: int
{
    case Connect     = 1;
    case ConnAck     = 2;
    case Publish     = 3;
    case PubAck      = 4;
    case PubRec      = 5;
    case PubRel      = 6;
    case PubComp     = 7;
    case Subscribe   = 8;
    case SubAck      = 9;
    case Unsubscribe = 10;
    case UnsubAck    = 11;
    case PingReq     = 12;
    case PingResp    = 13;
    case Disconnect  = 14;
    case Auth        = 15;

    /**
     * The exact low nibble this type's fixed header must carry, or `null` when
     * the bits are meaningful rather than reserved.
     *
     * `null` is only PUBLISH. Every other type has one legal value.
     */
    public function reservedFlags(): ?int
    {
        return match ($this) {
            self::Publish => null,

            // "Bits 3,2,1 and 0 ... are reserved and MUST be set to 0,0,1 and 0
            // respectively." The three types that carry a packet identifier the
            // peer is expected to ACT on rather than merely acknowledge.
            self::Subscribe, self::Unsubscribe, self::PubRel => 0b0010,

            default => 0b0000,
        };
    }

    /** Is $flags a legal low nibble for this packet type? */
    public function isFlagsValid(int $flags): bool
    {
        $required = $this->reservedFlags();

        if ($required === null) {
            // PUBLISH. Every combination of DUP/RETAIN is legal; only QoS 3 is
            // not, and that is checked where the QoS is read, because the
            // remedy differs (DISCONNECT 0x81 Malformed Packet).
            return ($flags & 0b0110) !== 0b0110;
        }

        return $flags === $required;
    }

    /**
     * Does a packet of this type have no variable header and no payload at all?
     *
     * PINGREQ and PINGRESP are two bytes total. Worth knowing explicitly
     * because a decoder that assumes every packet has something after the
     * length will read into the NEXT packet's header.
     */
    public function isEmpty(): bool
    {
        return $this === self::PingReq || $this === self::PingResp;
    }

    /**
     * Is this a packet only a client sends?
     *
     * Used to reject a broker that sends one. A CONNECT arriving from the
     * broker means either a broken broker or something that is not a broker —
     * and continuing to parse it would mean this client was no longer sure
     * which end of the conversation it was on.
     */
    public function isClientOnly(): bool
    {
        return match ($this) {
            self::Connect, self::Subscribe, self::Unsubscribe, self::PingReq => true,
            default => false,
        };
    }

    /** Is this a packet only a broker sends? */
    public function isServerOnly(): bool
    {
        return match ($this) {
            self::ConnAck, self::SubAck, self::UnsubAck, self::PingResp => true,
            default => false,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Connect     => 'CONNECT',
            self::ConnAck     => 'CONNACK',
            self::Publish     => 'PUBLISH',
            self::PubAck      => 'PUBACK',
            self::PubRec      => 'PUBREC',
            self::PubRel      => 'PUBREL',
            self::PubComp     => 'PUBCOMP',
            self::Subscribe   => 'SUBSCRIBE',
            self::SubAck      => 'SUBACK',
            self::Unsubscribe => 'UNSUBSCRIBE',
            self::UnsubAck    => 'UNSUBACK',
            self::PingReq     => 'PINGREQ',
            self::PingResp    => 'PINGRESP',
            self::Disconnect  => 'DISCONNECT',
            self::Auth        => 'AUTH',
        };
    }
}
