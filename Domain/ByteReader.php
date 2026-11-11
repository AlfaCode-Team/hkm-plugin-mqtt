<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * A bounds-checked cursor over one packet's bytes.
 *
 * WHY A CURSOR OBJECT AND NOT `unpack()` WITH OFFSETS
 * ---------------------------------------------------
 * Because MQTT's fields are self-describing lengths, and every read happens at
 * an offset the PEER chose. A CONNACK's property block says how long it is; a
 * PUBLISH's topic says how long it is; a property's value says how long it is.
 * Decoding is therefore a walk whose every step depends on untrusted data, and
 * the failure mode of doing that with manual offsets is not a crash — it is
 * reading the wrong bytes and believing them.
 *
 * Two specific bugs this class exists to make impossible:
 *
 * **1. A length that points past the end.** A two-byte string length of 60,000
 * inside a 40-byte packet. `substr()` answers that with a short string and no
 * complaint, so a decoder using it gets a silently truncated topic — and then
 * continues reading the NEXT field from an offset that is now wrong by 59,960
 * bytes. Every read here is bounds-checked first and throws, so a short field
 * is a refused packet rather than a corrupt one.
 *
 * **2. Trailing bytes nobody read.** A packet whose declared Remaining Length
 * exceeds the fields it actually contains leaves bytes over. That is a
 * malformed packet, and silently ignoring the remainder is how a decoder
 * accepts a packet it did not fully understand.
 * {@see self::assertConsumed()} makes the check explicit and cheap.
 *
 * THE CURSOR IS SCOPED TO ONE PACKET, DELIBERATELY
 * ------------------------------------------------
 * {@see PacketReader} has already used the Remaining Length to cut exactly one
 * packet's body out of the stream, so this reader's end IS the packet's end.
 * That is what lets {@see self::rest()} mean "the payload" — in a reader over
 * the whole stream it would mean "everything else that has arrived", which is a
 * different and much worse thing to hand to an application as a message body.
 *
 * A nested property block gets its own sub-reader via {@see self::slice()}, for
 * the same reason one level up: a property that lies about its length must not
 * be able to read past the block into the fields after it.
 */
final class ByteReader
{
    private int $offset = 0;

    public function __construct(private readonly string $buffer) {}

    public function remaining(): int
    {
        return \strlen($this->buffer) - $this->offset;
    }

    /**
     * Has every byte been consumed?
     *
     * Marked impure because it is: the answer depends on the cursor, which
     * every read moves. Without the annotation a static analyser caches the
     * first answer and concludes that a second `!isExhausted()` after some
     * reads is "always true" — which is exactly backwards, and the optional
     * trailing fields of a 5.0 acknowledgement are read with precisely that
     * pattern.
     *
     * @phpstan-impure
     */
    public function isExhausted(): bool
    {
        return $this->remaining() <= 0;
    }

    public function offset(): int
    {
        return $this->offset;
    }

    /**
     * One byte, 0..255.
     *
     * @throws MqttException when the buffer is exhausted
     */
    public function uint8(string $field = 'a byte'): int
    {
        $this->need(1, $field);

        return \ord($this->buffer[$this->offset++]);
    }

    /**
     * A Two Byte Integer, big-endian.
     *
     * @throws MqttException when fewer than two bytes remain
     */
    public function uint16(string $field = 'a two-byte integer'): int
    {
        $this->need(2, $field);

        $value = (\ord($this->buffer[$this->offset]) << 8) | \ord($this->buffer[$this->offset + 1]);
        $this->offset += 2;

        return $value;
    }

    /**
     * A Four Byte Integer, big-endian.
     *
     * Assembled by hand rather than with `unpack('N')` so the result is a
     * plain non-negative int on every platform: `unpack('N')` on a 32-bit
     * build returns a negative number for anything above 2^31, and a negative
     * Session Expiry Interval would be compared against a timeout and silently
     * treated as "already expired".
     *
     * @throws MqttException when fewer than four bytes remain
     */
    public function uint32(string $field = 'a four-byte integer'): int
    {
        $this->need(4, $field);

        $value = 0;

        for ($i = 0; $i < 4; $i++) {
            $value = ($value << 8) | \ord($this->buffer[$this->offset + $i]);
        }

        $this->offset += 4;

        return $value;
    }

    /**
     * A Variable Byte Integer.
     *
     * @throws MqttException when malformed, over $max, or incomplete — note
     *         that "incomplete" IS an error here, unlike in {@see VarInt}: this
     *         reader is scoped to one complete packet, so a varint running off
     *         its end is not "more is coming", it is a packet that lied
     */
    public function varInt(string $field = 'a variable byte integer', int $max = VarInt::MAX_VALUE): int
    {
        $decoded = VarInt::decode($this->buffer, $this->offset, $max);

        if ($decoded === null) {
            throw MqttException::malformedPacket(
                $field . ' is a Variable Byte Integer that runs past the end of the packet (at byte '
                . $this->offset . ' of ' . \strlen($this->buffer)
                . '). The packet declared a Remaining Length that does not cover its own fields',
            );
        }

        $this->offset += $decoded['length'];

        return $decoded['value'];
    }

    /**
     * An MQTT UTF-8 Encoded String: a two-byte length, then that many bytes.
     *
     * The contents ARE validated. It would be cheaper not to, and it would be
     * wrong: an ill-formed string is a Malformed Packet by the specification,
     * and a client that passed one through would hand an application a broken
     * topic to compare, log and store. Validating on the inbound side also
     * means this client never re-publishes a string it could not have produced.
     *
     * @throws MqttException when the length overruns the packet or the bytes
     *         are not a legal MQTT string
     */
    public function utf8(string $field = 'a string'): string
    {
        $length = $this->uint16($field . ' length');

        $this->need($length, $field);

        $value = substr($this->buffer, $this->offset, $length);
        $this->offset += $length;

        $reason = Utf8::reasonInvalid($value);

        if ($reason !== '') {
            throw MqttException::malformedPacket(
                $field . ' is not a legal MQTT UTF-8 Encoded String: ' . $reason,
            );
        }

        return $value;
    }

    /**
     * Binary Data: a two-byte length, then that many arbitrary bytes.
     *
     * Not validated as text, because it is not text — this carries Correlation
     * Data and Authentication Data, which are opaque by design.
     *
     * @throws MqttException when the length overruns the packet
     */
    public function binary(string $field = 'binary data'): string
    {
        $length = $this->uint16($field . ' length');

        $this->need($length, $field);

        $value = substr($this->buffer, $this->offset, $length);
        $this->offset += $length;

        return $value;
    }

    /**
     * A sub-reader over the next $length bytes, which this reader then skips.
     *
     * The containment is the point: a property block gets a reader that cannot
     * see past itself, so a property lying about its own length corrupts only
     * the block it is in and is caught by that block's
     * {@see self::assertConsumed()}.
     *
     * @throws MqttException when $length overruns the packet
     */
    public function slice(int $length, string $field = 'a nested block'): self
    {
        $this->need($length, $field);

        $slice = new self(substr($this->buffer, $this->offset, $length));
        $this->offset += $length;

        return $slice;
    }

    /**
     * Everything left, consuming it.
     *
     * This is the application payload of a PUBLISH, and it is correct ONLY
     * because this reader is scoped to one packet. See the class docblock.
     */
    public function rest(): string
    {
        $value        = substr($this->buffer, $this->offset);
        $this->offset = \strlen($this->buffer);

        return $value;
    }

    /**
     * Assert that nothing is left over.
     *
     * @throws MqttException when bytes remain, which means the packet carried
     *         fields this client did not account for — it must be refused
     *         rather than half-understood
     */
    public function assertConsumed(string $what): void
    {
        if ($this->remaining() > 0) {
            throw MqttException::malformedPacket(
                $what . ' has ' . $this->remaining() . ' byte(s) left over after every field it '
                . 'declares was read. Accepting that would mean acting on a packet whose contents are '
                . 'only partly understood',
            );
        }
    }

    /** @throws MqttException when fewer than $count bytes remain */
    private function need(int $count, string $field): void
    {
        if ($count < 0) {
            // Unreachable from a two-byte length, which cannot be negative.
            // Kept so a future caller passing a computed length cannot turn a
            // bounds check into a no-op.
            throw MqttException::malformedPacket(
                $field . ' asked for a negative number of bytes (' . $count . ')',
            );
        }

        if ($this->remaining() < $count) {
            throw MqttException::malformedPacket(
                $field . ' needs ' . $count . ' byte(s) but only ' . $this->remaining()
                . ' remain in the packet. A length field pointing past the end is the bug this check '
                . 'exists for: substr() would have returned a short string and the decode would have '
                . 'carried on at a wrong offset',
            );
        }
    }
}
