<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * The rules for an MQTT "UTF-8 Encoded String", which is every text field.
 *
 * WHY THIS IS NOT JUST `mb_check_encoding()`
 * ------------------------------------------
 * Because the one byte the specification singles out is the one a UTF-8
 * validator is obliged to accept.
 *
 *     [MQTT-1.5.4-2] A UTF-8 Encoded String MUST NOT include an encoding of
 *                    the null character U+0000.
 *     … If a receiver receives a Control Packet containing U+0000 it is a
 *       Malformed Packet.
 *
 * U+0000 is a perfectly legal Unicode code point with a perfectly legal
 * single-byte UTF-8 encoding, so every correct UTF-8 validator says yes to it.
 * Measured on this PHP build: `mb_check_encoding("\x00", 'UTF-8')` is TRUE and
 * `preg_match('//u', "\x00")` is 1. A client that validated strings by calling
 * one of those and stopping would pass the NUL straight through — and a NUL is
 * exactly what arrives when a topic is built from a C string, a fixed-width
 * database column, or a truncated buffer.
 *
 * So the NUL test is explicit and separate, and it is first.
 *
 * WHAT IS CHECKED, AND WHAT IS DELIBERATELY NOT
 * ---------------------------------------------
 * Refused, because the specification makes each one a Malformed Packet:
 *
 * - ill-formed UTF-8 — truncated sequences, bare continuation bytes, overlong
 *   encodings, anything above U+10FFFF;
 * - encodings of the surrogate range U+D800..U+DFFF [MQTT-1.5.4-1];
 * - U+0000 [MQTT-1.5.4-2];
 * - more than 65,535 bytes, which is simply what the two-byte length field can
 *   express.
 *
 * `mb_check_encoding` was measured to reject all of the first group and the
 * surrogates, so it does that work and this class does not re-implement a
 * UTF-8 decoder.
 *
 * ALLOWED, although the specification says SHOULD NOT:
 *
 * - the C0 and C1 control ranges (U+0001..U+001F, U+007F..U+009F);
 * - Unicode noncharacters such as U+FFFE;
 * - a leading byte-order mark, which [MQTT-1.5.4-3] says a receiver MUST NOT
 *   strip.
 *
 * Those are permitted because the specification permits them, and a client that
 * refused what the protocol allows would be unable to subscribe to a topic a
 * conforming broker is willing to serve. They are instead neutralised at the
 * only place they can do harm — the log line — by
 * {@see \Plugins\Mqtt\Domain\Exceptions\MqttException::printable()}.
 */
final class Utf8
{
    /** What a two-byte length prefix can express, and therefore the ceiling. */
    public const MAX_BYTES = 65535;

    private function __construct() {}

    /** Is $value usable in an MQTT UTF-8 Encoded String field? */
    public static function isValid(string $value): bool
    {
        return self::reasonInvalid($value) === '';
    }

    /**
     * Why $value cannot go in a string field, or `''` when it can.
     *
     * The reason is returned rather than a bool so a refusal can be logged with
     * something an operator can act on. "Invalid string" sends somebody to read
     * this source; "it contains U+0000 at byte 12" does not.
     */
    public static function reasonInvalid(string $value): string
    {
        // FIRST, and before the encoding check, because the encoding check
        // cannot see this: U+0000 is valid UTF-8. See the class docblock.
        $nul = strpos($value, "\x00");

        if ($nul !== false) {
            return 'it contains the null character U+0000 at byte ' . $nul
                . ', which [MQTT-1.5.4-2] forbids in any string field — note that this is still VALID '
                . 'UTF-8, so an encoding check alone does not catch it';
        }

        if (\strlen($value) > self::MAX_BYTES) {
            return 'it is ' . \strlen($value) . ' bytes, and the length prefix is two bytes, so the '
                . 'protocol cannot express more than ' . self::MAX_BYTES;
        }

        if (!mb_check_encoding($value, 'UTF-8')) {
            return 'it is not well-formed UTF-8 (a truncated sequence, a bare continuation byte, an '
                . 'overlong encoding, a surrogate in the U+D800..U+DFFF range, or a code point above '
                . 'U+10FFFF), and a receiver treats that as a Malformed Packet and closes the connection';
        }

        return '';
    }

    /**
     * Does $value contain code points the specification says SHOULD NOT appear?
     *
     * Not an error — see the class docblock — but worth surfacing, because a
     * topic carrying an ESC or a C1 control is far more likely to be a bug in
     * whatever built it than a deliberate choice, and the symptom otherwise is
     * a subscription that never matches anything for reasons invisible in a
     * terminal.
     */
    public static function hasDiscouragedCodePoints(string $value): bool
    {
        // The C0 range minus the NUL already refused above, plus DEL and C1.
        // Matched on code points rather than bytes: the C1 range is two bytes
        // in UTF-8, so a byte-wise test would both miss it and false-positive
        // on the continuation bytes of unrelated characters.
        return preg_match('/[\x{0001}-\x{001F}\x{007F}-\x{009F}]/u', $value) === 1;
    }
}
