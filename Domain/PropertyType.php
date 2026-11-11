<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * The seven wire types an MQTT 5.0 property value can have.
 *
 * The property block is TLV — identifier, then value — but the L is NOT on the
 * wire. There is no per-property length field: the identifier alone tells the
 * receiver how many bytes to read, which is why this mapping has to be exactly
 * right and why an unknown identifier is unrecoverable rather than skippable.
 *
 * That is the difference from a format like a TIFF tag or a TLS extension,
 * where an unknown entry carries its own length and can be stepped over. Here,
 * meeting identifier `0x07` — which does not exist — leaves a decoder with no
 * way to know whether the next byte is a one-byte value, the first of four, or
 * the next identifier. So {@see Properties::decode()} refuses the packet
 * instead of guessing, and that is forced by this type table, not a policy
 * choice.
 */
enum PropertyType
{
    case Byte;
    case TwoByteInteger;
    case FourByteInteger;
    case VariableByteInteger;
    case Utf8String;
    case BinaryData;
    case Utf8StringPair;

    public function label(): string
    {
        return match ($this) {
            self::Byte                => 'Byte',
            self::TwoByteInteger      => 'Two Byte Integer',
            self::FourByteInteger     => 'Four Byte Integer',
            self::VariableByteInteger => 'Variable Byte Integer',
            self::Utf8String          => 'UTF-8 Encoded String',
            self::BinaryData          => 'Binary Data',
            self::Utf8StringPair      => 'UTF-8 String Pair',
        };
    }
}
