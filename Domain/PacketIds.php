<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * Allocates Packet Identifiers, and enforces the two rules about them.
 *
 * THE RULES
 * ---------
 *     [MQTT-2.2.1-3] The Client MUST assign it a non-zero Packet Identifier
 *                    that is currently unused.
 *     … A Packet Identifier cannot be used by more than one command at any
 *      time.
 *     … The Packet Identifier becomes available for reuse after the sender has
 *      processed the corresponding acknowledgement packet.
 *
 * Non-zero and unused, and the two have different consequences.
 *
 * **Zero** is simply not a valid identifier, and a QoS 0 PUBLISH must contain
 * no identifier at all rather than a zero one — including the two bytes shifts
 * every byte of the payload and corrupts the message.
 *
 * **Reuse while in flight** is the subtle one, and it does not fail loudly: the
 * acknowledgements are matched by identifier alone, so two in-flight publishes
 * sharing one id means the first PUBACK completes BOTH of them. One message is
 * then believed delivered when it was never acknowledged, and if the broker
 * later acks the second, that ack matches nothing and is dropped. Nothing
 * errors. A monotonic counter with no in-flight set gets this right until it
 * wraps at 65,535 and then gets it wrong forever, on a long-lived publisher,
 * which is to say in production and not in a test.
 *
 * So: a counter for the next candidate, AND a set of what is in flight, and the
 * candidate skips anything in the set.
 *
 * WHY EXHAUSTION THROWS RATHER THAN WAITS
 * ---------------------------------------
 * All 65,535 identifiers in flight means 65,535 publishes have gone out and
 * none has been acknowledged. That is not back-pressure to ride out — it is a
 * broker that has stopped acknowledging, and the useful response is to say so.
 * Blocking would turn a reportable fault into a hung process.
 *
 * In practice `Receive Maximum` bites long before that: a 5.0 broker advertises
 * how many unacknowledged QoS 1/2 publishes it will accept (brokers commonly
 * say 20 or 100), and exceeding it is `0x93 Receive Maximum exceeded`, which
 * closes the connection. {@see self::withLimit()} applies that advertised
 * ceiling so this client refuses locally instead of being disconnected.
 */
final class PacketIds
{
    public const MIN = 1;
    public const MAX = 65535;

    /** @var array<int, true> the in-flight set, keyed by identifier */
    private array $inFlight = [];

    private int $next = self::MIN;

    /**
     * @param int $limit the most identifiers that may be in flight at once —
     *                   from the broker's `Receive Maximum`, or {@see self::MAX}
     */
    public function __construct(private int $limit = self::MAX) {}

    /**
     * Apply the broker's advertised `Receive Maximum`.
     *
     * Called after CONNACK. Lowering the limit below what is already in flight
     * is possible in principle (a reconnect that resumed a session) and is not
     * an error: the existing publishes are already out, and the limit simply
     * blocks new ones until they drain.
     */
    public function withLimit(int $limit): void
    {
        $this->limit = max(1, min($limit, self::MAX));
    }

    public function inFlightCount(): int
    {
        return \count($this->inFlight);
    }

    public function limit(): int
    {
        return $this->limit;
    }

    public function isInFlight(int $id): bool
    {
        return isset($this->inFlight[$id]);
    }

    /**
     * Take the next free identifier and mark it in flight.
     *
     * @throws MqttException when the in-flight limit is reached
     */
    public function allocate(): int
    {
        if (\count($this->inFlight) >= $this->limit) {
            throw MqttException::cannotEncode(
                'all ' . $this->limit . ' permitted packet identifiers are in flight, which means that '
                . 'many QoS 1 or 2 publishes have gone out unacknowledged. '
                . ($this->limit < self::MAX
                    ? 'That is the Receive Maximum this broker advertised in CONNACK, so sending more '
                      . 'would earn 0x93 Receive Maximum exceeded and a closed connection.'
                    : 'The broker has stopped acknowledging.')
                . ' Nothing was written: this is reported rather than waited on, because a hung publish '
                . 'is harder to diagnose than a failed one',
            );
        }

        // Linear probe from the rotating cursor. Bounded by MAX iterations, and
        // guaranteed to find a slot because the count check above proved one
        // exists. Rotating rather than always restarting at 1 keeps an
        // identifier out of use for as long as possible after it is released,
        // which matters because a late acknowledgement for a released id must
        // not be matched against a freshly allocated publish.
        for ($attempt = 0; $attempt < self::MAX; $attempt++) {
            $candidate = $this->next;

            // Wrap to MIN, never to 0 — zero is not a valid identifier.
            $this->next = $candidate >= self::MAX ? self::MIN : $candidate + 1;

            if (!isset($this->inFlight[$candidate])) {
                $this->inFlight[$candidate] = true;

                return $candidate;
            }
        }

        // Unreachable: the count check proved a free identifier exists and the
        // loop visits every one. Kept so that a future change to either half
        // cannot turn this into an infinite loop or a duplicate allocation.
        throw MqttException::cannotEncode(
            'no free packet identifier was found although ' . \count($this->inFlight) . ' of '
            . $this->limit . ' are in flight; the allocator and its in-flight set disagree',
        );
    }

    /**
     * Mark $id complete and available again.
     *
     * Returns false when $id was not in flight, which is how a duplicate or
     * unsolicited acknowledgement is detected. Not an exception: a broker
     * re-sending a PUBACK is rude rather than fatal, and the connection is
     * still perfectly usable — but a caller that silently accepted it would be
     * completing a publish that no longer exists.
     */
    public function release(int $id): bool
    {
        if (!isset($this->inFlight[$id])) {
            return false;
        }

        unset($this->inFlight[$id]);

        return true;
    }

    /**
     * Forget everything in flight.
     *
     * For a reconnect with a clean start, where the broker has discarded its
     * session state. Carrying identifiers across that boundary would mean
     * waiting for acknowledgements the broker no longer knows it owes.
     */
    public function reset(): void
    {
        $this->inFlight = [];
        $this->next     = self::MIN;
    }

    /**
     * The identifiers currently in flight, for diagnostics.
     *
     * @return list<int>
     */
    public function pending(): array
    {
        return array_keys($this->inFlight);
    }
}
