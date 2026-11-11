<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * MQTT 3.1.1 and 5.0 — one client, two wire formats.
 *
 * WHY BOTH, WHEN 5.0 IS STRICTLY BETTER
 * -------------------------------------
 * Because the broker decides, and often it is not yours. MQTT's reach is in
 * devices and in managed brokers, and plenty of both speak only 3.1.1 — among
 * them `nats-server`, which this toolchain already pins and provisions, so the
 * zero-extra-dependency way to get a broker here is a 3.1.1 one.
 *
 * Supporting only 5.0 would mean the client could not talk to the broker the
 * rest of the toolchain installs. Supporting only 3.1.1 would give up shared
 * subscriptions, reason codes and session expiry, and would misreport every
 * failure as "connection closed".
 *
 * WHAT ACTUALLY DIFFERS ON THE WIRE
 * ---------------------------------
 * Less than the version numbers suggest, and all of it in two places:
 *
 * 1. **Properties.** Every 5.0 packet except PINGREQ/PINGRESP carries a
 *    property block — a Variable Byte Integer length followed by TLV entries.
 *    In 3.1.1 that block DOES NOT EXIST, not even as a zero length. Emitting
 *    the single `0x00` byte of an empty 5.0 property block to a 3.1.1 broker
 *    shifts every byte after it, and the broker reads the next field at the
 *    wrong offset. {@see self::hasProperties()} is therefore consulted by the
 *    encoder for every packet, not just the interesting ones.
 *
 * 2. **Reason codes.** 5.0 returns a one-byte reason on CONNACK, PUBACK,
 *    SUBACK, UNSUBACK, DISCONNECT and AUTH, from one shared table. 3.1.1 has a
 *    CONNACK "return code" with five values of its own and nothing anywhere
 *    else — no UNSUBACK reason, no DISCONNECT from the broker at all.
 *    {@see ReasonCode::fromV311ConnAck()} maps the five, and the gaps are why
 *    a 3.1.1 connection cannot distinguish an eviction from a dead network.
 *
 * Everything else — the fixed header, the varint, the UTF-8 string framing, the
 * QoS flows, the topic rules — is identical, which is what makes one client
 * reasonable rather than two clients in a trench coat.
 */
enum ProtocolVersion: int
{
    case V311 = 4;
    case V5   = 5;

    /**
     * Accept what an operator would plausibly write in `MQTT_VERSION`.
     *
     * `3.1.1`, `311`, `4`, `3.1`, `5`, `5.0`. Returns `null` for anything else
     * rather than guessing — an unreadable version is a configuration error
     * worth reporting, and silently defaulting it would mean a typo chose the
     * wire format.
     *
     * `3.1` maps to 3.1.1 on purpose. True MQTT 3.1 (protocol level 3) used
     * the protocol name `MQIsdp` and a 23-byte client-id ceiling; it is not
     * implemented here, and an operator writing `3.1` means the common version,
     * not the 2010 one.
     */
    public static function parse(string $raw): ?self
    {
        return match (strtolower(trim($raw))) {
            '5', '5.0', 'v5', 'mqtt5'                 => self::V5,
            '4', '3.1.1', '311', '3.1', 'v4', 'mqtt4' => self::V311,
            default                                    => null,
        };
    }

    /**
     * Does a packet of this version carry a property block?
     *
     * True for every 5.0 packet that has a variable header. PINGREQ and
     * PINGRESP have no variable header in either version, so the encoder never
     * asks.
     */
    public function hasProperties(): bool
    {
        return $this === self::V5;
    }

    /**
     * The Protocol Name field, which is NOT the same in both.
     *
     * Both modern versions use `MQTT`; only 3.1 used `MQIsdp`. The method
     * exists so the encoder reads the value from the version rather than
     * hard-coding a literal that a future case would silently inherit.
     */
    public function protocolName(): string
    {
        return 'MQTT';
    }

    /** Can the broker send a DISCONNECT, or does it just close the socket? */
    public function hasServerDisconnect(): bool
    {
        return $this === self::V5;
    }

    /** Are shared subscriptions (`$share/<name>/<filter>`) available? */
    public function hasSharedSubscriptions(): bool
    {
        return $this === self::V5;
    }

    public function label(): string
    {
        return match ($this) {
            self::V311 => '3.1.1',
            self::V5   => '5.0',
        };
    }
}
