<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\VarInt;

/**
 * The Remaining Length codec — MQTT's principal parsing hazard.
 *
 * Three of these tests cover the three ways this goes wrong, and each of them
 * is a real failure rather than a specification nicety:
 *
 * - an unbounded length is a memory exhaustion primitive costing four bytes;
 * - a loop with no byte counter consumes the entire stream on `0x80` repeated;
 * - a non-minimal encoding gives one value several byte representations.
 */
final class VarIntTest extends TestCase
{
    #[DataProvider('boundaries')]
    public function test_round_trip(int $value, string $expected): void
    {
        self::assertSame(
            bin2hex($expected),
            bin2hex(VarInt::encode($value)),
            'encoding ' . $value,
        );

        $decoded = VarInt::decode($expected);

        self::assertNotNull($decoded);
        self::assertSame($value, $decoded['value']);
        self::assertSame(\strlen($expected), $decoded['length']);
        self::assertSame(\strlen($expected), VarInt::sizeOf($value));
    }

    /**
     * The boundary values from the specification's own table, plus each side of
     * every byte-count change — which is where an off-by-one in the `% 128`
     * arithmetic shows up.
     *
     * @return iterable<string, array{int, string}>
     */
    public static function boundaries(): iterable
    {
        yield 'zero'          => [0, "\x00"];
        yield 'one'           => [1, "\x01"];
        yield 'max one byte'  => [127, "\x7F"];
        yield 'min two bytes' => [128, "\x80\x01"];
        yield 'max two bytes' => [16383, "\xFF\x7F"];
        yield 'min three'     => [16384, "\x80\x80\x01"];
        yield 'max three'     => [2097151, "\xFF\xFF\x7F"];
        yield 'min four'      => [2097152, "\x80\x80\x80\x01"];
        yield 'max four'      => [268435455, "\xFF\xFF\xFF\x7F"];
    }

    /**
     * Zero must be ONE byte, not the empty string.
     *
     * A `while ($value > 0)` loop emits nothing for zero, which makes a PINGREQ
     * a one-byte packet and desynchronises the peer's parser for the rest of
     * the connection. Hence the do-while in the encoder.
     */
    public function test_zero_encodes_to_exactly_one_byte(): void
    {
        self::assertSame("\x00", VarInt::encode(0));
        self::assertSame(1, \strlen(VarInt::encode(0)));
    }

    // ─── Hazard 1: an unbounded length is a memory attack ───────────────────

    /**
     * Four legal bytes saying "the next 256 MiB belong to this packet". A
     * decoder that believes it buffers 256 MiB; the sender spent four bytes.
     */
    public function test_a_value_over_the_callers_limit_is_refused(): void
    {
        $maxBytes = "\xFF\xFF\xFF\x7F";

        // Decodable in principle…
        $decoded = VarInt::decode($maxBytes, 0, VarInt::MAX_VALUE);
        self::assertNotNull($decoded);
        self::assertSame(268435455, $decoded['value']);

        // …and refused against a real packet-size limit.
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/over the 8192-byte limit/');

        VarInt::decode($maxBytes, 0, 8192);
    }

    public function test_refusing_an_oversized_length_marks_the_connection_lost(): void
    {
        try {
            VarInt::decode("\xFF\xFF\xFF\x7F", 0, 1024);
            self::fail('expected a refusal');
        } catch (MqttException $e) {
            // A length-prefixed stream cannot be resynchronised after a bad
            // length: having mis-read one, there is no way to find the start of
            // the next packet.
            self::assertTrue($e->connectionLost);
        }
    }

    // ─── Hazard 2: the loop must be bounded ─────────────────────────────────

    /**
     * `0x80` repeated is the attack on a `while (byte & 0x80)` loop with no
     * counter: it consumes the whole stream looking for a terminator that never
     * comes, and the shift overflows long before that.
     */
    public function test_a_fifth_continuation_byte_is_refused_rather_than_consuming_the_stream(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/continuation bit set on its fourth byte/');

        VarInt::decode("\x80\x80\x80\x80\x01");
    }

    public function test_a_long_run_of_continuation_bytes_is_refused_at_the_fourth(): void
    {
        $this->expectException(MqttException::class);

        VarInt::decode(str_repeat("\x80", 10_000));
    }

    // ─── Hazard 3: minimal encoding ─────────────────────────────────────────

    /**
     * [MQTT-1.5.5-1]. Without it, `0` has five spellings — so anything that
     * compares, hashes, signs or deduplicates packets can be made to disagree
     * with anything else that does.
     */
    #[DataProvider('nonMinimal')]
    public function test_a_non_minimal_encoding_is_refused(string $bytes, string $label): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/non-minimal|MQTT-1.5.5-1/');

        VarInt::decode($bytes);
    }

    /** @return iterable<string, array{string, string}> */
    public static function nonMinimal(): iterable
    {
        yield 'zero in two bytes'   => ["\x80\x00", '0 as 0x80 0x00'];
        yield 'zero in three bytes' => ["\x80\x80\x00", '0 as three bytes'];
        yield 'zero in four bytes'  => ["\x80\x80\x80\x00", '0 as four bytes'];
        yield '127 in two bytes'    => ["\xFF\x00", '127 spelled long'];
    }

    // ─── Partial input is NOT an error ──────────────────────────────────────

    /**
     * "Not enough bytes yet" is the ordinary, constant state of a stream
     * reader: a four-byte length can legitimately arrive as four TCP segments.
     * Reporting it as an error would make every segmented read a failure.
     */
    public function test_an_incomplete_varint_returns_null_rather_than_throwing(): void
    {
        self::assertNull(VarInt::decode(''), 'no bytes at all');
        self::assertNull(VarInt::decode("\x80"), 'one byte, more promised');
        self::assertNull(VarInt::decode("\x80\x80"), 'two bytes, more promised');
        self::assertNull(VarInt::decode("\x80\x80\x80"), 'three bytes, more promised');
    }

    /**
     * The distinction between "incomplete" and "malformed" is the continuation
     * bit on the FOURTH byte: three bytes promising more is incomplete, four
     * bytes promising more cannot be a varint.
     */
    public function test_three_continuation_bytes_are_incomplete_but_four_are_malformed(): void
    {
        self::assertNull(VarInt::decode("\x80\x80\x80"));

        $this->expectException(MqttException::class);
        VarInt::decode("\x80\x80\x80\x80");
    }

    public function test_decoding_at_an_offset_reads_from_there(): void
    {
        $decoded = VarInt::decode("\xFF\xFF\x80\x01", 2);

        self::assertNotNull($decoded);
        self::assertSame(128, $decoded['value']);
        self::assertSame(2, $decoded['length']);
    }

    public function test_an_offset_past_the_end_is_incomplete_not_an_error(): void
    {
        self::assertNull(VarInt::decode("\x01", 5));
    }

    // ─── Encoding bounds ────────────────────────────────────────────────────

    public function test_a_negative_value_cannot_be_encoded(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/cannot be negative/');

        VarInt::encode(-1);
    }

    public function test_a_value_over_the_protocol_maximum_cannot_be_encoded(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/at most 268435455/');

        VarInt::encode(VarInt::MAX_VALUE + 1);
    }

    /**
     * An encode failure leaves the connection usable: nothing was written,
     * which is the whole point of validating before encoding.
     */
    public function test_an_encode_refusal_does_not_mark_the_connection_lost(): void
    {
        try {
            VarInt::encode(-1);
            self::fail('expected a refusal');
        } catch (MqttException $e) {
            self::assertFalse($e->connectionLost);
            self::assertStringContainsString('Nothing was written', $e->getMessage());
        }
    }

    /**
     * Every value round-trips. A sweep rather than a sample, because the
     * `% 128` / `intdiv` arithmetic fails at byte boundaries and a sampled test
     * can walk straight past them.
     */
    public function test_a_sweep_of_values_round_trips(): void
    {
        foreach ([0, 1, 2, 126, 127, 128, 129, 254, 255, 256, 16382, 16383, 16384, 16385,
                  2097150, 2097151, 2097152, 2097153, 268435454, 268435455] as $value) {
            $decoded = VarInt::decode(VarInt::encode($value));

            self::assertNotNull($decoded, (string) $value);
            self::assertSame($value, $decoded['value'], (string) $value);
        }
    }
}
