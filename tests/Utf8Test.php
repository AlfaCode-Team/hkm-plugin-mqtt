<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\Utf8;

/**
 * The MQTT string rules — and the one that a UTF-8 validator cannot catch.
 */
final class Utf8Test extends TestCase
{
    /**
     * THE TEST THIS CLASS EXISTS FOR.
     *
     * `U+0000` is forbidden in an MQTT string by [MQTT-1.5.4-2], and it is
     * PERFECTLY VALID UTF-8 — it is a legal code point with a legal one-byte
     * encoding. So every correct UTF-8 validator accepts it, and a client that
     * validated strings by calling one and stopping would pass the NUL straight
     * through to a broker that treats it as a Malformed Packet and closes the
     * connection.
     *
     * The first two assertions pin PHP's actual behaviour, so that if a future
     * PHP changed it this test would say so rather than silently becoming
     * redundant.
     */
    public function test_a_null_byte_is_valid_utf8_and_still_refused(): void
    {
        self::assertTrue(
            mb_check_encoding("\x00", 'UTF-8'),
            'U+0000 IS valid UTF-8 — this is why the NUL check must be separate',
        );
        self::assertSame(
            1,
            preg_match('//u', "\x00"),
            'and PCRE\'s /u modifier accepts it too',
        );

        self::assertFalse(Utf8::isValid("\x00"));
        self::assertFalse(Utf8::isValid("before\x00after"));
        self::assertStringContainsString('U+0000', Utf8::reasonInvalid("before\x00after"));
        self::assertStringContainsString('byte 6', Utf8::reasonInvalid("before\x00after"));
    }

    /**
     * [MQTT-1.5.4-1] forbids encoded surrogates, and `mb_check_encoding`
     * rejects them — which is why this class does not re-implement a UTF-8
     * decoder. Measured, not assumed.
     */
    public function test_ill_formed_utf8_is_refused(): void
    {
        $cases = [
            'lone surrogate'      => "\xED\xA0\x80",
            'overlong NUL'        => "\xC0\x80",
            'truncated sequence'  => "\xC3",
            'bare continuation'   => "\x80",
            'above U+10FFFF'      => "\xF5\x80\x80\x80",
        ];

        foreach ($cases as $label => $bytes) {
            self::assertFalse(Utf8::isValid($bytes), $label);
            self::assertStringContainsString('UTF-8', Utf8::reasonInvalid($bytes), $label);
        }
    }

    public function test_well_formed_utf8_is_accepted(): void
    {
        foreach (['', 'ascii', 'é', '温度', '🌡', "line\nbreak", "tab\there"] as $value) {
            self::assertTrue(Utf8::isValid($value), bin2hex($value));
        }
    }

    /**
     * The two-byte length prefix is the ceiling, so this is not a policy choice
     * — the protocol cannot express more.
     */
    public function test_a_string_over_65535_bytes_is_refused(): void
    {
        self::assertTrue(Utf8::isValid(str_repeat('a', 65535)));
        self::assertFalse(Utf8::isValid(str_repeat('a', 65536)));
        self::assertStringContainsString('65535', Utf8::reasonInvalid(str_repeat('a', 65536)));
    }

    /**
     * The specification says SHOULD NOT for control characters and
     * noncharacters, so they are PERMITTED here — a client that refused what
     * the protocol allows could not subscribe to a topic a conforming broker
     * is willing to serve. They are neutralised in the log line instead.
     */
    public function test_discouraged_code_points_are_allowed_but_reported(): void
    {
        self::assertTrue(Utf8::isValid("bell\x07"), 'SHOULD NOT, not MUST NOT');
        self::assertTrue(Utf8::hasDiscouragedCodePoints("bell\x07"));

        self::assertTrue(Utf8::isValid("\x1B[31m"), 'an ANSI escape is legal MQTT');
        self::assertTrue(Utf8::hasDiscouragedCodePoints("\x1B[31m"));

        self::assertFalse(Utf8::hasDiscouragedCodePoints('ordinary text'));
        self::assertFalse(Utf8::hasDiscouragedCodePoints('température'));
    }

    /**
     * The C1 range is TWO bytes in UTF-8, so a byte-wise test would both miss
     * it and false-positive on the continuation bytes of unrelated characters.
     * `é` is `0xC3 0xA9`, whose second byte is in the C1 range byte-wise.
     */
    public function test_the_c1_range_is_detected_by_code_point_not_by_byte(): void
    {
        self::assertTrue(
            Utf8::hasDiscouragedCodePoints("\u{0085}"),
            'U+0085 NEL is in the C1 range and must be detected',
        );
        self::assertFalse(
            Utf8::hasDiscouragedCodePoints('é'),
            'é is 0xC3 0xA9 — a byte-wise C1 test would wrongly flag it',
        );
    }

    /** [MQTT-1.5.4-3]: a BOM must not be stripped, so it is ordinary content. */
    public function test_a_byte_order_mark_is_ordinary_content(): void
    {
        self::assertTrue(Utf8::isValid("\xEF\xBB\xBFtopic"));
        self::assertFalse(Utf8::hasDiscouragedCodePoints("\xEF\xBB\xBFtopic"));
    }

    public function test_a_noncharacter_is_allowed(): void
    {
        // U+FFFE. SHOULD NOT appear, and a receiver only MAY treat it as
        // malformed — so refusing it here would be stricter than the protocol.
        self::assertTrue(Utf8::isValid("\xEF\xBF\xBE"));
    }
}
