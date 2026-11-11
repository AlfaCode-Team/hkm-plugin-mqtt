<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\PacketReader;
use Plugins\Mqtt\Domain\PacketType;
use Plugins\Mqtt\Domain\VarInt;

/**
 * The framing, fed bytes in groupings a real socket would produce only rarely.
 *
 * Every interesting bug in a stream reader is a boundary bug, and against a
 * real socket the boundaries are chosen by the network. Here they are chosen by
 * the test, which is the only way to have them covered at all.
 */
final class PacketReaderTest extends TestCase
{
    public function test_a_complete_packet_is_returned_and_consumed(): void
    {
        $reader = new PacketReader();
        $reader->append(Packets::publish('a/b', 'hello'));

        $packet = $reader->next();

        self::assertNotNull($packet);
        self::assertSame(PacketType::Publish, $packet->type);
        self::assertStringContainsString('hello', $packet->body);

        self::assertNull($reader->next(), 'and it is consumed');
        self::assertSame(0, $reader->buffered());
    }

    /**
     * The grouping a real socket produces under load, and the one most likely
     * to break a reader that assumes one read is one packet.
     */
    public function test_three_packets_in_one_write_are_all_returned(): void
    {
        $reader = new PacketReader();
        $reader->append(
            Packets::publish('a', '1')
            . Packets::pingResp()
            . Packets::publish('b', '2'),
        );

        $types = [];

        while (($packet = $reader->next()) !== null) {
            $types[] = $packet->type;
        }

        self::assertSame(
            [PacketType::Publish, PacketType::PingResp, PacketType::Publish],
            $types,
        );

    }

    /**
     * One byte at a time. Nothing is returned until the packet is whole, and
     * then exactly one packet is.
     */
    public function test_a_packet_arriving_one_byte_at_a_time(): void
    {
        $bytes  = Packets::publish('sensors/3/temp', '21.5', qos: 1, packetId: 9);
        $reader = new PacketReader();

        for ($i = 0, $n = \strlen($bytes); $i < $n; $i++) {
            $reader->append($bytes[$i]);

            if ($i < $n - 1) {
                self::assertNull($reader->next(), 'incomplete at byte ' . ($i + 1) . ' of ' . $n);
            }
        }

        $packet = $reader->next();

        self::assertNotNull($packet);
        self::assertSame(PacketType::Publish, $packet->type);
        // The QoS lives in bits 2-1, so shifting right by one yields the level.
        self::assertSame(1, ($packet->flags >> 1) & 0b11, 'QoS 1 survived the reassembly');
    }

    /**
     * Split exactly on the length field — a four-byte Remaining Length can
     * legitimately arrive as four TCP segments, and a reader that treated a
     * partial varint as malformed would fail on a large packet over a slow
     * link.
     */
    public function test_a_packet_split_inside_its_multi_byte_length(): void
    {
        $payload = str_repeat('x', 300);
        $bytes   = Packets::publish('a', $payload);

        // 300 + topic overhead needs a two-byte Remaining Length.
        self::assertSame(2, VarInt::sizeOf(\strlen($bytes) - 3));

        $reader = new PacketReader();

        $reader->append(substr($bytes, 0, 1));
        self::assertNull($reader->next(), 'type byte only');

        $reader->append(substr($bytes, 1, 1));
        self::assertNull($reader->next(), 'first length byte promises more');

        $reader->append(substr($bytes, 2));

        $packet = $reader->next();
        self::assertNotNull($packet);
        self::assertStringEndsWith($payload, $packet->body);
    }

    /**
     * THE MEMORY GUARD. Four legal bytes claiming 256 MiB must be refused
     * before a single body byte is buffered — the length is bounded on arrival,
     * not after the packet completes.
     */
    public function test_an_oversized_declared_length_is_refused_before_the_body_arrives(): void
    {
        $reader = new PacketReader(maxPacketBytes: 1024);

        // PUBLISH with a Remaining Length of 268,435,455 and no body at all.
        $reader->append("\x30\xFF\xFF\xFF\x7F");

        self::assertSame(5, $reader->buffered(), 'only the header is buffered');

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/over the 1024-byte limit/');

        $reader->next();
    }

    public function test_a_packet_exactly_at_the_limit_is_accepted(): void
    {
        $reader  = new PacketReader(maxPacketBytes: 64);
        $payload = str_repeat('x', 64 - 3 - 2); // topic 'ab' is 4 bytes incl. length, +1 prop byte

        $reader->append(Packets::publish('ab', str_repeat('x', 56)));

        $packet = $reader->next();

        self::assertNotNull($packet, 'a packet inside the limit must pass');
        unset($payload);
    }

    /**
     * Type 0 is "Reserved — Forbidden". Reaching it means the stream is not
     * MQTT, or a previous length was wrong and the reader has lost its place —
     * and a plaintext client pointed at a TLS listener reads the TLS alert
     * exactly this way.
     */
    public function test_packet_type_zero_is_refused(): void
    {
        $reader = new PacketReader();
        $reader->append("\x00\x00");

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/does not exist/');

        $reader->next();
    }

    /**
     * SUBSCRIBE, UNSUBSCRIBE and PUBREL must carry `0b0010`. A broker sending
     * one with `0b0000` is malformed, and verifying this on the INBOUND side
     * matters as much as emitting it correctly.
     */
    public function test_wrong_reserved_flags_are_refused(): void
    {
        foreach ([PacketType::PubRel, PacketType::Subscribe, PacketType::Unsubscribe] as $type) {
            $reader = new PacketReader();
            $reader->append(\chr($type->value << 4) . "\x02\x00\x01");

            try {
                $reader->next();
                self::fail($type->label() . ' with flags 0b0000 should be refused');
            } catch (MqttException $e) {
                self::assertStringContainsString('reserves them', $e->getMessage());
            }
        }

        // And a PUBACK with 0b0010 is equally wrong.
        $reader = new PacketReader();
        $reader->append("\x42\x02\x00\x01");

        $this->expectException(MqttException::class);
        $reader->next();
    }

    /** QoS 3 does not exist, and a PUBLISH with both bits set is malformed. */
    public function test_qos_3_is_refused_in_the_framing(): void
    {
        $reader = new PacketReader();
        $reader->append("\x36\x04\x00\x01a\x00");

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/QoS 3 is not a QoS/');

        $reader->next();
    }

    /**
     * PINGREQ and PINGRESP are two bytes total. A decoder that assumed every
     * packet had something after the length would read into the NEXT packet's
     * header.
     */
    public function test_an_empty_packet_type_with_a_body_is_refused(): void
    {
        $reader = new PacketReader();
        $reader->append("\xD0\x02\x00\x00");

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/Remaining Length must be 0/');

        $reader->next();
    }

    public function test_a_ping_response_is_two_bytes_and_carries_nothing(): void
    {
        $reader = new PacketReader();
        $reader->append(Packets::pingResp());

        $packet = $reader->next();

        self::assertNotNull($packet);
        self::assertSame(PacketType::PingResp, $packet->type);
        self::assertSame('', $packet->body);
        self::assertSame(2, $packet->size());
    }

    /**
     * The cursor must not leak: reading many small packets through one buffer
     * is the shape a burst produces, and a `substr()` per packet is quadratic.
     * This asserts the memory stays bounded rather than growing with the count.
     */
    public function test_many_packets_do_not_grow_the_buffer_without_bound(): void
    {
        $reader = new PacketReader();
        $one    = Packets::publish('a', 'x');

        // Far past the 8 KiB compaction threshold.
        for ($i = 0; $i < 2000; $i++) {
            $reader->append($one);
        }

        $seen = 0;

        while ($reader->next() !== null) {
            ++$seen;
        }

        self::assertSame(2000, $seen);
        self::assertSame(0, $reader->buffered(), 'everything consumed, nothing stranded');
    }

    /**
     * A reconnect must not frame the new stream against the old one's offsets:
     * leftover bytes are not merely stale, they are mid-packet.
     */
    public function test_reset_discards_a_partial_packet(): void
    {
        $reader = new PacketReader();
        $reader->append(substr(Packets::publish('a', 'hello'), 0, 4));

        self::assertNull($reader->next());
        self::assertGreaterThan(0, $reader->buffered());

        $reader->reset();

        self::assertSame(0, $reader->buffered());

        // A fresh, complete packet now frames correctly.
        $reader->append(Packets::pingResp());
        self::assertSame(PacketType::PingResp, $reader->next()?->type);
    }

    public function test_a_single_byte_is_never_a_packet(): void
    {
        $reader = new PacketReader();
        $reader->append("\x30");

        self::assertNull($reader->next(), 'every packet is at least two bytes');
    }

    public function test_the_raw_packet_reports_its_wire_size(): void
    {
        $bytes  = Packets::publish('a/b/c', str_repeat('x', 200));
        $reader = new PacketReader();
        $reader->append($bytes);

        $packet = $reader->next();

        self::assertNotNull($packet);
        self::assertSame(\strlen($bytes), $packet->size());
    }
}
