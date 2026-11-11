<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * Turns a byte stream into whole packets, one at a time.
 *
 * THE PROBLEM THIS SOLVES IS NOT "PARSE A PACKET"
 * -----------------------------------------------
 * It is that TCP has no message boundaries. One `fread()` can return half a
 * packet, three packets, or two and a half — and which one it returns depends
 * on the network, not on anything a test chose. So every interesting bug here
 * is a boundary bug, and the only way to have them tested is to make the
 * framing a separate, synchronous object that can be fed bytes in any grouping.
 *
 * Which is what this is: {@see self::append()} takes whatever arrived and
 * {@see self::next()} returns a packet or `null`. The tests feed it a packet
 * one byte at a time, two packets in one write, and a packet split exactly on
 * its length field — groupings a real socket would produce only occasionally
 * and never on demand.
 *
 * READ THE LENGTH, THEN WAIT. NEVER READ THE BODY TO FIND THE END.
 * ---------------------------------------------------------------
 * MQTT is length-prefixed, so the end of a packet is known before any of its
 * body arrives. That is a gift — there is no delimiter to scan for and no
 * escaping to undo — and it comes with one obligation: the length arrives from
 * an untrusted peer and is believed.
 *
 * So the length is bounded BEFORE the body is buffered. A packet claiming
 * 268 MB is refused on its fourth byte, not after a quarter of a gigabyte has
 * been accumulated waiting for it to complete. That is the whole reason
 * `$maxPacketBytes` is a constructor argument rather than a check somewhere
 * downstream: downstream is after the memory has been spent.
 *
 * THE CURSOR, AND WHY IT IS NOT A `substr()` PER PACKET
 * ----------------------------------------------------
 * The obvious implementation consumes with `$this->buffer = substr($this->buffer,
 * $consumed)`. That copies the entire remaining buffer on every packet, so a
 * read that delivered 500 small packets copies the tail 500 times — quadratic
 * in the number of packets per read, which is exactly the shape a burst
 * produces.
 *
 * Instead the buffer is kept and a cursor moves through it, and the already-read
 * prefix is discarded only when it grows past {@see self::COMPACT_THRESHOLD}.
 * Amortised linear, one copy per 8 KB rather than one per packet.
 */
final class PacketReader
{
    /**
     * Discard the consumed prefix once it exceeds this.
     *
     * A straight trade: compacting more often costs copies, less often costs
     * memory. 8 KB bounds the waste at 8 KB per connection, which for ten
     * thousand connections is 80 MB — and this client holds one.
     */
    private const COMPACT_THRESHOLD = 8192;

    private string $buffer = '';

    private int $cursor = 0;

    /**
     * @param int $maxPacketBytes the largest packet this client will accept,
     *        checked against the declared Remaining Length before any of the
     *        body is buffered
     */
    public function __construct(private readonly int $maxPacketBytes = 8388608) {}

    public function append(string $bytes): void
    {
        $this->buffer .= $bytes;
    }

    /** Bytes received but not yet formed into a packet. */
    public function buffered(): int
    {
        return \strlen($this->buffer) - $this->cursor;
    }

    /**
     * The next complete packet, or `null` when more bytes are needed.
     *
     * @throws MqttException when the stream is not MQTT — which is unrecoverable
     *         and closes the connection, because a length-prefixed stream offers
     *         no way to resynchronise after one bad length
     */
    public function next(): ?RawPacket
    {
        $available = \strlen($this->buffer) - $this->cursor;

        if ($available < 2) {
            // Every packet is at least two bytes: the type/flags byte and a
            // one-byte Remaining Length. PINGREQ and PINGRESP are exactly two.
            return null;
        }

        $header = \ord($this->buffer[$this->cursor]);
        $typeId = $header >> 4;
        $flags  = $header & 0x0F;

        $type = PacketType::tryFrom($typeId);

        if ($type === null) {
            // Type 0 is "Reserved — Forbidden" and there is no type above 15,
            // so this is only reachable with a 0 nibble. It means the stream is
            // not MQTT at all, or this client has lost its place in it.
            throw MqttException::malformedPacket(
                'packet type ' . $typeId . ' does not exist (the first byte was 0x'
                . strtoupper(str_pad(dechex($header), 2, '0', \STR_PAD_LEFT))
                . '). Type 0 is reserved and forbidden, so either this is not an MQTT stream — a '
                . 'plaintext client pointed at a TLS listener reads the TLS alert this way — or a '
                . 'previous length was wrong and the reader is no longer aligned to a packet boundary',
            );
        }

        if (!$type->isFlagsValid($flags)) {
            $required = $type->reservedFlags();

            throw MqttException::malformedPacket(
                $type->label() . ' arrived with fixed-header flags 0b'
                . str_pad(decbin($flags), 4, '0', \STR_PAD_LEFT)
                . ($required !== null
                    ? ', but [3.' . $type->value . '.1] reserves them and requires 0b'
                      . str_pad(decbin($required), 4, '0', \STR_PAD_LEFT)
                    : ', which sets both QoS bits — QoS 3 is not a QoS'),
            );
        }

        // Bound the length before buffering the body. See the class docblock.
        $length = VarInt::decode($this->buffer, $this->cursor + 1, $this->maxPacketBytes);

        if ($length === null) {
            // The varint is incomplete. Legitimate: a four-byte length can
            // arrive as four segments.
            return null;
        }

        $headerSize = 1 + $length['length'];
        $total      = $headerSize + $length['value'];

        if ($available < $total) {
            // The body has not fully arrived. Nothing is copied and nothing is
            // consumed, so the next call re-reads the same header — which is
            // cheap, and much simpler than carrying a half-parsed state across
            // calls.
            return null;
        }

        if ($type->isEmpty() && $length['value'] !== 0) {
            throw MqttException::malformedPacket(
                $type->label() . ' has no variable header and no payload, so its Remaining Length must '
                . 'be 0; this one declared ' . $length['value'],
            );
        }

        $body = substr($this->buffer, $this->cursor + $headerSize, $length['value']);

        $this->cursor += $total;
        $this->compactIfWasteful();

        return new RawPacket($type, $flags, $body);
    }

    /**
     * Discard everything buffered.
     *
     * For a reconnect: bytes from the previous connection are not merely stale,
     * they are mid-packet, so carrying them into a fresh connection would frame
     * the new stream against the old one's offsets.
     */
    public function reset(): void
    {
        $this->buffer = '';
        $this->cursor = 0;
    }

    private function compactIfWasteful(): void
    {
        if ($this->cursor < self::COMPACT_THRESHOLD) {
            return;
        }

        $this->buffer = substr($this->buffer, $this->cursor);
        $this->cursor = 0;
    }
}
