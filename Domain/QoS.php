<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * Quality of Service — and what each level actually costs and buys.
 *
 * THE LEVEL IS A STATEMENT ABOUT DUPLICATES, NOT ABOUT RELIABILITY
 * ---------------------------------------------------------------
 * The names mislead. "At least once" and "exactly once" sound like a spectrum
 * from careless to careful, and they are not — they are three different
 * contracts, and only one of them is free:
 *
 * - {@see self::AtMostOnce} (0) is fire and forget. One packet, no
 *   acknowledgement, no state on either side. The message is lost if the
 *   connection drops mid-flight, and the publisher never finds out.
 *
 * - {@see self::AtLeastOnce} (1) is one round trip (PUBLISH → PUBACK). The
 *   message cannot be silently lost, and it CAN BE DELIVERED TWICE: if the
 *   PUBACK is lost the publisher re-sends with DUP set, and the subscriber has
 *   no way to know it already handled it. A handler that is not idempotent is
 *   wrong at QoS 1, and the duplicate only appears when the network misbehaves
 *   — which is to say, never in development.
 *
 * - {@see self::ExactlyOnce} (2) is two round trips (PUBLISH → PUBREC →
 *   PUBREL → PUBCOMP) and requires BOTH ends to remember the packet identifier
 *   across the exchange. It is the only level that makes the "exactly once"
 *   claim, and it pays for it in latency and in state that must survive a
 *   reconnect to mean anything.
 *
 * WHY THE PORT DEFAULTS TO 0
 * --------------------------
 * {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort} promises
 * at-most-once and says so in as many words: a subscriber that was not
 * connected does not receive the message, and nothing replays it. That is
 * exactly QoS 0, and promising more through that interface would be a promise
 * the Redis and NATS-core adapters could not keep.
 *
 * QoS 1 and 2 are reachable through the native client surface
 * ({@see \Plugins\Mqtt\Application\Services\MqttClient}), where the caller can
 * see what it is buying — in particular that a QoS 2 publish is four packets
 * and will block until the exchange completes.
 */
enum QoS: int
{
    case AtMostOnce  = 0;
    case AtLeastOnce = 1;
    case ExactlyOnce = 2;

    /**
     * Decode the two QoS bits of a PUBLISH's fixed header, or `null` for 3.
     *
     * `null` rather than an exception because the caller's remedy is specific
     * and non-negotiable: "A PUBLISH Packet MUST NOT have both QoS bits set to
     * 1", a receiver treats it as a Malformed Packet, and the response is
     * DISCONNECT with `0x81`. Returning `null` keeps that decision with the
     * decoder rather than hiding it in a constructor.
     */
    public static function tryFromBits(int $bits): ?self
    {
        return self::tryFrom($bits & 0b11);
    }

    /** Does this level require a Packet Identifier on the PUBLISH? */
    public function needsPacketId(): bool
    {
        // "A PUBLISH packet MUST NOT contain a Packet Identifier if its QoS
        // value is set to 0" — so this is not an optimisation. Including one at
        // QoS 0 shifts every following byte and corrupts the payload.
        return $this !== self::AtMostOnce;
    }

    /**
     * The packet type that acknowledges a PUBLISH at this level, if any.
     *
     * QoS 2 answers PUBREC first; PUBCOMP ends the exchange but is not the
     * immediate response, which is why this returns PUBREC and not PUBCOMP.
     */
    public function acknowledgedBy(): ?PacketType
    {
        return match ($this) {
            self::AtMostOnce  => null,
            self::AtLeastOnce => PacketType::PubAck,
            self::ExactlyOnce => PacketType::PubRec,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::AtMostOnce  => 'at most once (0)',
            self::AtLeastOnce => 'at least once (1)',
            self::ExactlyOnce => 'exactly once (2)',
        };
    }
}
