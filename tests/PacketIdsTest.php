<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\PacketIds;

/**
 * The identifier allocator, and the bug a plain counter has.
 */
final class PacketIdsTest extends TestCase
{
    public function test_identifiers_are_non_zero_and_distinct_while_in_flight(): void
    {
        $ids  = new PacketIds();
        $seen = [];

        for ($i = 0; $i < 1000; $i++) {
            $id = $ids->allocate();

            self::assertGreaterThanOrEqual(PacketIds::MIN, $id);
            self::assertLessThanOrEqual(PacketIds::MAX, $id);
            self::assertNotSame(0, $id, 'zero is not a valid identifier');
            self::assertArrayNotHasKey($id, $seen, 'reused while in flight');

            $seen[$id] = true;
        }

        self::assertSame(1000, $ids->inFlightCount());
    }

    /**
     * THE BUG A PLAIN COUNTER HAS, and it does not fail loudly.
     *
     * Acknowledgements are matched by identifier alone. Two in-flight publishes
     * sharing one identifier means the first PUBACK completes BOTH — one
     * message is believed delivered when it was never acknowledged, and a later
     * ack for the second matches nothing and is dropped. A monotonic counter
     * with no in-flight set gets this right until it wraps at 65,535, and
     * wrong for ever after, on a long-lived publisher.
     */
    public function test_a_released_identifier_is_not_immediately_reissued(): void
    {
        $ids   = new PacketIds();
        $first = $ids->allocate();

        $ids->release($first);

        // The cursor has moved on, so the next allocation is a different
        // identifier even though the first is free again. That keeps a LATE
        // acknowledgement for the released id from matching a fresh publish.
        self::assertNotSame($first, $ids->allocate());
    }

    /**
     * The wrap must go to 1, never to 0: zero is not a valid identifier, and a
     * `% 65536` would produce it.
     */
    public function test_the_counter_wraps_to_one_and_never_to_zero(): void
    {
        $ids = new PacketIds();

        // Exhaust the space, then free it all, so the cursor is at the top.
        for ($i = 0; $i < PacketIds::MAX; $i++) {
            $ids->allocate();
        }

        self::assertSame(PacketIds::MAX, $ids->inFlightCount());

        for ($i = PacketIds::MIN; $i <= PacketIds::MAX; $i++) {
            $ids->release($i);
        }

        self::assertSame(0, $ids->inFlightCount());

        // The next 10 allocations after a full wrap must all be valid.
        for ($i = 0; $i < 10; $i++) {
            $id = $ids->allocate();

            self::assertGreaterThanOrEqual(1, $id, 'the wrap must not produce 0');
        }
    }

    /**
     * Exhaustion throws rather than blocking. All identifiers in flight means
     * the broker has stopped acknowledging — a reportable fault, and blocking
     * would turn it into a hung process.
     */
    public function test_exhaustion_throws_rather_than_waiting(): void
    {
        $ids = new PacketIds(limit: 3);

        $ids->allocate();
        $ids->allocate();
        $ids->allocate();

        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/all 3 permitted packet identifiers are in flight/');

        $ids->allocate();
    }

    /**
     * The broker's Receive Maximum is a hard ceiling: exceeding it is
     * `0x93 Receive Maximum exceeded`, which CLOSES the connection — so
     * refusing locally costs one publish rather than every subscription on the
     * link.
     */
    public function test_the_brokers_receive_maximum_is_applied(): void
    {
        $ids = new PacketIds();

        self::assertSame(PacketIds::MAX, $ids->limit());

        $ids->withLimit(2);

        self::assertSame(2, $ids->limit());

        $ids->allocate();
        $ids->allocate();

        try {
            $ids->allocate();
            self::fail('the third should be refused');
        } catch (MqttException $e) {
            self::assertStringContainsString('Receive Maximum this broker advertised', $e->getMessage());
            self::assertFalse($e->connectionLost, 'nothing was written, so the link is fine');
        }
    }

    /** A Receive Maximum of 0 is a Protocol Error; clamping beats trusting it. */
    public function test_a_nonsense_limit_is_clamped(): void
    {
        $ids = new PacketIds();

        $ids->withLimit(0);
        self::assertSame(1, $ids->limit(), 'zero would refuse every QoS 1 publish for ever');

        $ids->withLimit(999_999);
        self::assertSame(PacketIds::MAX, $ids->limit());
    }

    /**
     * A duplicate or unsolicited acknowledgement is detected, not thrown. A
     * broker re-sending a PUBACK is rude rather than fatal — but a caller that
     * accepted it silently would complete a publish that no longer exists.
     */
    public function test_releasing_an_identifier_that_is_not_in_flight_reports_false(): void
    {
        $ids = new PacketIds();
        $id  = $ids->allocate();

        self::assertTrue($ids->release($id));
        self::assertFalse($ids->release($id), 'a second release is unsolicited');
        self::assertFalse($ids->release(60_000), 'never allocated');
    }

    public function test_in_flight_identifiers_are_reported_for_diagnostics(): void
    {
        $ids = new PacketIds();
        $a   = $ids->allocate();
        $b   = $ids->allocate();

        self::assertSame([$a, $b], $ids->pending());
        self::assertTrue($ids->isInFlight($a));

        $ids->release($a);

        self::assertSame([$b], $ids->pending());
        self::assertFalse($ids->isInFlight($a));
    }

    /**
     * A clean-start reconnect means the broker discarded its session state, so
     * carrying identifiers across would mean waiting for acknowledgements the
     * broker no longer knows it owes.
     */
    public function test_reset_clears_everything_in_flight(): void
    {
        $ids = new PacketIds();
        $ids->allocate();
        $ids->allocate();

        $ids->reset();

        self::assertSame(0, $ids->inFlightCount());
        self::assertSame(1, $ids->allocate(), 'and the cursor starts again at 1');
    }
}
