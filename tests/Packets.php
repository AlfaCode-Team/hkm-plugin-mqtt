<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use Plugins\Mqtt\Domain\PacketType;
use Plugins\Mqtt\Domain\VarInt;

/**
 * Hand-built broker packets, for scripting a {@see ScriptedConnection}.
 *
 * WHY THESE ARE ASSEMBLED BY HAND AND NOT BY THE ENCODER
 * -----------------------------------------------------
 * Because using `Encoder` to build the bytes that `Decoder` is tested against
 * would make the test pass whenever the two agree — including when both are
 * wrong in the same way. A codec tested against itself verifies only that it is
 * self-consistent, which is the one property a round-trip test cannot fail to
 * demonstrate and the least interesting thing about it.
 *
 * So these are built from the specification's field order, byte by byte, and
 * the test asserts the decoder reads them as the specification says. The
 * encoder is then checked SEPARATELY against bytes written out the same way.
 * Where the two meet is in `BrokerTest`, against a real broker, which is the
 * only arbiter that is neither of them.
 */
final class Packets
{
    private function __construct() {}

    /** A complete packet from its type, flags and body. */
    public static function wrap(PacketType $type, int $flags, string $body): string
    {
        return \chr(((($type->value << 4) | $flags)) & 0xFF) . VarInt::encode(\strlen($body)) . $body;
    }

    /** A length-prefixed MQTT string. */
    public static function str(string $value): string
    {
        return \chr((\strlen($value) >> 8) & 0xFF) . \chr(\strlen($value) & 0xFF) . $value;
    }

    public static function uint16(int $value): string
    {
        return \chr(($value >> 8) & 0xFF) . \chr($value & 0xFF);
    }

    /**
     * CONNACK.
     *
     * @param bool $v5 false builds the MQTT 3.1.1 shape, where the code byte is
     *        a five-value "return code" and there is NO property block at all —
     *        the difference this plugin's version handling exists for
     */
    public static function connAck(
        int $code = 0,
        bool $sessionPresent = false,
        string $properties = '',
        bool $v5 = true,
    ): string {
        return self::wrap(
            PacketType::ConnAck,
            0,
            \chr($sessionPresent ? 1 : 0) . \chr($code & 0xFF) . ($v5 ? VarInt::encode(\strlen($properties)) . $properties : ''),
        );
    }

    /** PUBLISH. */
    public static function publish(
        string $topic,
        string $payload,
        int $qos = 0,
        ?int $packetId = null,
        bool $retain = false,
        bool $dup = false,
        string $properties = '',
        bool $v5 = true,
    ): string {
        $body = self::str($topic)
            . ($packetId !== null ? self::uint16($packetId) : '')
            . ($v5 ? VarInt::encode(\strlen($properties)) . $properties : '')
            . $payload;

        $flags = ($qos << 1) | ($retain ? 1 : 0) | ($dup ? 8 : 0);

        return self::wrap(PacketType::Publish, $flags, $body);
    }

    /** PUBACK, PUBREC, PUBREL or PUBCOMP. */
    public static function ack(
        PacketType $type,
        int $packetId,
        ?int $reasonCode = null,
        string $properties = '',
    ): string {
        $body = self::uint16($packetId);

        if ($reasonCode !== null) {
            $body .= \chr($reasonCode & 0xFF);

            if ($properties !== '') {
                $body .= VarInt::encode(\strlen($properties)) . $properties;
            }
        }

        return self::wrap($type, $type->reservedFlags() ?? 0, $body);
    }

    /**
     * SUBACK or UNSUBACK.
     *
     * @param list<int> $codes one per filter, in the order they were requested
     */
    public static function subAck(
        int $packetId,
        array $codes,
        PacketType $type = PacketType::SubAck,
        string $properties = '',
        bool $v5 = true,
    ): string {
        $body = self::uint16($packetId)
            . ($v5 ? VarInt::encode(\strlen($properties)) . $properties : '');

        foreach ($codes as $code) {
            $body .= \chr($code & 0xFF);
        }

        return self::wrap($type, 0, $body);
    }

    public static function pingResp(): string
    {
        return self::wrap(PacketType::PingResp, 0, '');
    }

    /** A broker-sent DISCONNECT — MQTT 5.0 only. */
    public static function disconnect(int $reasonCode = 0, string $properties = ''): string
    {
        $body = \chr($reasonCode & 0xFF);

        if ($properties !== '') {
            $body .= VarInt::encode(\strlen($properties)) . $properties;
        }

        return self::wrap(PacketType::Disconnect, 0, $body);
    }

    /** A single-byte property: identifier then value. */
    public static function byteProperty(int $id, int $value): string
    {
        return \chr($id & 0xFF) . \chr($value & 0xFF);
    }

    public static function uint16Property(int $id, int $value): string
    {
        return \chr($id & 0xFF) . self::uint16($value);
    }

    public static function uint32Property(int $id, int $value): string
    {
        return \chr($id & 0xFF) . \chr(($value >> 24) & 0xFF) . \chr(($value >> 16) & 0xFF)
            . \chr(($value >> 8) & 0xFF) . \chr($value & 0xFF);
    }

    public static function stringProperty(int $id, string $value): string
    {
        return \chr($id & 0xFF) . self::str($value);
    }
}
