<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * One complete packet, framed but not interpreted.
 *
 * The seam between {@see PacketReader}, whose job is to find where packets
 * begin and end, and {@see Decoder}, whose job is to read their fields. Keeping
 * them apart is what lets the framing be tested against a byte stream arriving
 * one byte at a time, and the field decoding be tested against a complete
 * packet, without either test having to arrange the other's awkward cases.
 *
 * `$body` is everything after the fixed header — the variable header and the
 * payload — and it is exactly as long as the Remaining Length said. That
 * boundary is what makes {@see ByteReader::rest()} mean "this packet's payload"
 * rather than "every byte that has arrived".
 */
final readonly class RawPacket
{
    public function __construct(
        public PacketType $type,
        /** The fixed header's low nibble: meaningful for PUBLISH, reserved otherwise. */
        public int $flags,
        public string $body,
    ) {}

    public function reader(): ByteReader
    {
        return new ByteReader($this->body);
    }

    /** Total wire size, for diagnostics and byte accounting. */
    public function size(): int
    {
        return 1 + VarInt::sizeOf(\strlen($this->body)) + \strlen($this->body);
    }

    public function describe(): string
    {
        return $this->type->label() . ' (' . $this->size() . ' bytes)';
    }
}
