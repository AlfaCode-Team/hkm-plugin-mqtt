<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * An accumulator for the primitive MQTT wire types.
 *
 * THE ONE JOB THAT MATTERS: REFUSE LOCALLY WHAT THE BROKER WOULD CLOSE FOR
 * -----------------------------------------------------------------------
 * Every string written through {@see self::utf8()} is validated first. That is
 * not symmetry with {@see ByteReader} for its own sake — it is because of what
 * the broker does with a bad one. A Malformed Packet is not answered with an
 * error the client can log and move on from; the specification requires the
 * receiver to CLOSE THE NETWORK CONNECTION. So one over-long user property, or
 * one client id carrying a NUL from a fixed-width database column, does not
 * fail that one publish — it drops the connection, taking every subscription on
 * it, and the client's reconnect loop then does it again.
 *
 * Validating here turns that into a thrown exception with the offending field
 * named and nothing written.
 *
 * WHY THE LENGTH PREFIX IS WRITTEN FROM THE BYTES AND NEVER PASSED IN
 * ------------------------------------------------------------------
 * There is no method here that takes a length. Every length is computed from
 * `strlen()` of the value being written, immediately before writing it, so a
 * declared length and the bytes that follow cannot disagree. A disagreement is
 * the one error a length-prefixed protocol cannot survive: the peer reads the
 * declared count, which means it reads either into the next field or past the
 * packet, and everything after that is nonsense.
 */
final class ByteWriter
{
    private string $buffer = '';

    public function uint8(int $value): self
    {
        if ($value < 0 || $value > 0xFF) {
            throw MqttException::cannotEncode(
                'a byte field was given ' . $value . ', which does not fit in one byte',
            );
        }

        $this->buffer .= \chr($value);

        return $this;
    }

    public function uint16(int $value): self
    {
        if ($value < 0 || $value > 0xFFFF) {
            throw MqttException::cannotEncode(
                'a Two Byte Integer field was given ' . $value . ', which does not fit in two bytes',
            );
        }

        $this->buffer .= \chr(($value >> 8) & 0xFF) . \chr($value & 0xFF);

        return $this;
    }

    public function uint32(int $value): self
    {
        if ($value < 0 || $value > 0xFFFFFFFF) {
            throw MqttException::cannotEncode(
                'a Four Byte Integer field was given ' . $value . ', which does not fit in four bytes',
            );
        }

        $this->buffer .= \chr(($value >> 24) & 0xFF)
            . \chr(($value >> 16) & 0xFF)
            . \chr(($value >> 8) & 0xFF)
            . \chr($value & 0xFF);

        return $this;
    }

    public function varInt(int $value): self
    {
        $this->buffer .= VarInt::encode($value);

        return $this;
    }

    /**
     * An MQTT UTF-8 Encoded String.
     *
     * @param  string $field what this is, for the exception message — the
     *                       whole value of refusing early is that the operator
     *                       learns WHICH field was wrong
     * @throws MqttException when the value is not a legal MQTT string
     */
    public function utf8(string $value, string $field = 'a string field'): self
    {
        $reason = Utf8::reasonInvalid($value);

        if ($reason !== '') {
            throw MqttException::invalidString($field, $reason);
        }

        return $this->uint16(\strlen($value))->raw($value);
    }

    /**
     * Binary Data — opaque bytes with a two-byte length.
     *
     * @throws MqttException when longer than a two-byte length can express
     */
    public function binary(string $value, string $field = 'a binary field'): self
    {
        if (\strlen($value) > Utf8::MAX_BYTES) {
            throw MqttException::invalidString(
                $field,
                'it is ' . \strlen($value) . ' bytes and Binary Data carries a two-byte length, so the '
                . 'protocol cannot express more than ' . Utf8::MAX_BYTES,
            );
        }

        return $this->uint16(\strlen($value))->raw($value);
    }

    /**
     * Bytes with no length prefix at all.
     *
     * Only for a PUBLISH payload, whose length is implied by the Remaining
     * Length, and for appending an already-encoded block.
     */
    public function raw(string $bytes): self
    {
        $this->buffer .= $bytes;

        return $this;
    }

    public function length(): int
    {
        return \strlen($this->buffer);
    }

    public function bytes(): string
    {
        return $this->buffer;
    }

    /**
     * Wrap these bytes in a fixed header, producing a complete packet.
     *
     * The Remaining Length is computed from the accumulated bytes, never
     * supplied — see the class docblock.
     *
     * @param  int $flags the low nibble; validated against the type, because
     *                    SUBSCRIBE, UNSUBSCRIBE and PUBREL require `0b0010`
     *                    and a zero there is answered by a closed socket
     *                    rather than an error
     * @throws MqttException when $flags is not legal for $type
     */
    public function asPacket(PacketType $type, int $flags = 0): string
    {
        if (!$type->isFlagsValid($flags)) {
            $required = $type->reservedFlags();

            throw MqttException::cannotEncode(
                'the fixed-header flags 0b' . str_pad(decbin($flags), 4, '0', \STR_PAD_LEFT)
                . ' are not legal for ' . $type->label()
                . ($required !== null
                    ? ', which requires 0b' . str_pad(decbin($required), 4, '0', \STR_PAD_LEFT)
                      . '. A receiver treats any other value as a Malformed Packet and closes the '
                      . 'connection rather than replying with an error'
                    : ' (QoS 3 is not a QoS)'),
            );
        }

        // Masked to a byte. The type is 1..15 so the shift cannot overflow in
        // practice, but saying so explicitly keeps the fixed header one byte
        // whatever a future enum case does — and a two-byte chr() here would
        // shift every packet this client sends.
        return \chr(((($type->value << 4) | ($flags & 0x0F))) & 0xFF)
            . VarInt::encode(\strlen($this->buffer))
            . $this->buffer;
    }
}
