<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * The Variable Byte Integer — MQTT's Remaining Length, and its main parsing hazard.
 *
 * WHAT IT IS
 * ----------
 * Seven bits of payload per byte, the top bit saying "another byte follows".
 * One to four bytes, so `0` … `268,435,455`:
 *
 *     0x00                      →           0
 *     0x7F                      →         127
 *     0x80 0x01                 →         128
 *     0xFF 0xFF 0xFF 0x7F       → 268,435,455
 *
 * It appears as the Remaining Length of every packet, as the length of every
 * MQTT 5.0 property block, and as the Subscription Identifier property. It is
 * the first field this client reads from an untrusted peer, and everything
 * after it is read at an offset it chose.
 *
 * THE THREE WAYS THIS GOES WRONG, EACH OF WHICH IS GUARDED HERE
 * ------------------------------------------------------------
 * **1. An unbounded length is a memory exhaustion primitive.** `0xFF 0xFF 0xFF
 * 0x7F` is four legal bytes that say "the next 256 MiB belong to this packet".
 * A decoder that believes it will buffer 256 MiB per packet, and the attack
 * costs the sender four bytes. So the ceiling is not the protocol's 268 MB — it
 * is the caller's `$max`, which {@see PacketReader} takes from
 * `MQTT_MAX_PACKET_BYTES`, and a packet claiming more is refused BEFORE a
 * single payload byte is buffered.
 *
 * **2. A fifth byte must terminate the decode, not continue it.** The field is
 * four bytes and the specification's own decoding pseudocode raises
 * "Malformed Variable Byte Integer" past that. A loop written as
 * `while (byte & 0x80)` with no counter does not merely mis-read: fed `0x80`
 * repeated, it consumes the entire rest of the stream looking for a byte that
 * never comes, and the shift overflows long before that. The counter is the
 * guard, and it is why this is a class with a test rather than four lines
 * inline.
 *
 * **3. A non-minimal encoding is forbidden, and the reason is not pedantry.**
 * `[MQTT-1.5.5-1]`: "The encoded value MUST use the minimum number of bytes
 * necessary to represent the value." Without that rule `0` has five spellings
 * (`0x00`, `0x80 0x00`, `0x80 0x80 0x00`, …). Accepting all of them means the
 * same logical packet has several byte representations, so anything that
 * compares, hashes, signs or deduplicates packets can be made to disagree with
 * anything else that does. Refusing it keeps the mapping one-to-one.
 *
 * WHY DECODING RETURNS `null` RATHER THAN THROWING ON A SHORT BUFFER
 * -----------------------------------------------------------------
 * "I have not received enough bytes yet" is the ordinary, constant state of a
 * stream reader — a four-byte length can legitimately arrive as four separate
 * TCP segments. It is not an error and must not be reported as one. A malformed
 * encoding is a different matter and throws, because the connection cannot
 * recover: having mis-read a length there is no way to find the next packet.
 *
 * The two are distinguished by the decoder having seen the continuation bit on
 * the LAST byte available: that means "more is coming", whereas the same bit on
 * the fourth byte means "this cannot be a varint".
 */
final class VarInt
{
    /** `0xFF 0xFF 0xFF 0x7F` — what four bytes can express. */
    public const MAX_VALUE = 268435455;

    /** The field is at most four bytes. Not negotiable, and the loop bound. */
    public const MAX_BYTES = 4;

    private function __construct() {}

    /**
     * Encode $value as one to four bytes.
     *
     * @throws MqttException when $value is negative or above {@see self::MAX_VALUE}
     */
    public static function encode(int $value): string
    {
        if ($value < 0) {
            throw MqttException::cannotEncode(
                'a Variable Byte Integer cannot be negative, and ' . $value . ' was given',
            );
        }

        if ($value > self::MAX_VALUE) {
            throw MqttException::cannotEncode(
                'a Variable Byte Integer holds at most ' . self::MAX_VALUE . ' (four bytes), and '
                . $value . ' was given. For a Remaining Length this means the packet is too large for '
                . 'the protocol, whatever the broker would have allowed',
            );
        }

        $out = '';

        // Do-while, not while: zero is one byte (0x00), and a plain `while
        // ($value > 0)` emits the empty string for it — a Remaining Length of
        // nothing, which is how a PINGREQ becomes a one-byte packet and
        // desynchronises the peer's parser.
        do {
            $byte  = $value % 128;
            $value = intdiv($value, 128);

            if ($value > 0) {
                $byte |= 0x80;
            }

            $out .= \chr($byte);
        } while ($value > 0);

        return $out;
    }

    /**
     * Decode the varint at $offset in $buffer.
     *
     * @param  int $max the largest value the caller will accept; a correctly
     *                  encoded larger one is still refused, because believing
     *                  it is what costs the memory
     * @return array{value: int, length: int}|null `null` when $buffer does not
     *                  yet hold the whole field — not an error
     * @throws MqttException when the encoding is malformed, or the value
     *                  exceeds $max
     */
    public static function decode(string $buffer, int $offset = 0, int $max = self::MAX_VALUE): ?array
    {
        $value      = 0;
        $multiplier = 1;
        $available  = \strlen($buffer);

        for ($i = 0; $i < self::MAX_BYTES; $i++) {
            $at = $offset + $i;

            if ($at >= $available) {
                // Out of bytes. Every byte so far had the continuation bit set
                // (or we would have returned), so more is genuinely expected.
                return null;
            }

            $byte   = \ord($buffer[$at]);
            $value += ($byte & 0x7F) * $multiplier;

            if (($byte & 0x80) === 0) {
                $length = $i + 1;

                // [MQTT-1.5.5-1]. A multi-byte encoding whose final byte
                // contributes nothing is a longer spelling of a shorter value.
                // Checked here rather than by re-encoding and comparing,
                // because that would allocate on every packet.
                if ($length > 1 && ($byte & 0x7F) === 0) {
                    throw MqttException::malformedPacket(
                        'the Variable Byte Integer at byte ' . $offset . ' is encoded in ' . $length
                        . ' bytes but its last byte contributes nothing, so it is a non-minimal spelling '
                        . 'of ' . $value . '. [MQTT-1.5.5-1] requires the minimum number of bytes, '
                        . 'because otherwise one value has several byte representations and anything '
                        . 'that compares or deduplicates packets can be made to disagree',
                    );
                }

                if ($value > $max) {
                    throw MqttException::malformedPacket(
                        'the Variable Byte Integer at byte ' . $offset . ' is ' . $value
                        . ', over the ' . $max . '-byte limit this client accepts. Nothing was buffered: '
                        . 'four bytes claiming a huge length is all it would take to exhaust memory, so '
                        . 'the length is checked before the body is read',
                    );
                }

                return ['value' => $value, 'length' => $length];
            }

            $multiplier *= 128;
        }

        // Four bytes consumed and the fourth still said "more follows".
        throw MqttException::malformedPacket(
            'the Variable Byte Integer at byte ' . $offset . ' has the continuation bit set on its '
            . 'fourth byte, and the field is at most ' . self::MAX_BYTES . ' bytes. A decoder that kept '
            . 'going here would consume the rest of the stream looking for a terminator that never '
            . 'comes',
        );
    }

    /** How many bytes $value will occupy. */
    public static function sizeOf(int $value): int
    {
        return match (true) {
            $value < 128      => 1,
            $value < 16384    => 2,
            $value < 2097152  => 3,
            default           => 4,
        };
    }
}
