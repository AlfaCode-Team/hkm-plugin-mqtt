<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * The Will — a message the broker publishes when this client disappears.
 *
 * WHY MQTT HAS THIS AND OTHER BUSES DO NOT
 * ----------------------------------------
 * MQTT was designed for devices on links that fail without saying so, where the
 * useful question is not "did the last message arrive" but "is that sensor
 * still there". A will is the protocol's answer: the client declares, at
 * CONNECT time, a message the BROKER will publish on its behalf if the
 * connection ends without a proper DISCONNECT.
 *
 * So a status topic can be correct without anybody polling:
 *
 *     connect  → publish `services/exporter/status` = "up", retained
 *     will     → `services/exporter/status` = "down", retained
 *
 * A subscriber reading that topic gets the truth whether the process exited
 * cleanly, was killed, or had its network cut — and because the will is
 * retained, a subscriber arriving later gets it too.
 *
 * THE DISTINCTION THAT MAKES IT WORK, AND THE ONE THAT BREAKS IT
 * -------------------------------------------------------------
 * The will fires on an ABNORMAL end. A client that sends DISCONNECT is
 * declaring a clean exit and the broker DISCARDS the will — which is correct
 * (a planned shutdown is not a fault) and is also the trap: a process that
 * exits cleanly publishes no "down", so a will alone cannot be a general
 * liveness signal. The deliberate way to exit AND fire the will is a DISCONNECT
 * carrying reason code `0x04 Disconnect with Will Message`, which exists for
 * exactly this.
 *
 * `delayInterval` (5.0 only) holds the will back for that many seconds, so a
 * client that reconnects inside the window never appears to have gone down. It
 * is what stops a thirty-second network blip from looking like an outage to
 * everything watching the status topic. In 3.1.1 there is no delay: the will
 * fires as soon as the broker notices, which it does after 1.5x keep-alive.
 */
final readonly class Will
{
    /**
     * @param string $topic   validated when the CONNECT is encoded, not here —
     *                        a will topic is a publish topic and goes through
     *                        {@see Topic::assertName()} with the same rules,
     *                        including the refusal of wildcards
     * @param int    $delayInterval seconds to wait before publishing; MQTT 5.0
     *                        only, ignored on 3.1.1 because the property does
     *                        not exist there and sending it would be malformed
     * @param ?Properties $properties extra will properties (content type,
     *                        response topic, user properties). Nullable rather
     *                        than defaulting to an empty bag because a default
     *                        parameter cannot be a static call and
     *                        {@see Properties} has no public constructor;
     *                        {@see self::properties()} resolves the null
     */
    public function __construct(
        public string $topic,
        public string $payload,
        public QoS $qos = QoS::AtMostOnce,
        public bool $retain = false,
        public int $delayInterval = 0,
        public ?Properties $properties = null,
    ) {}

    /** The declared properties, with the Will Delay Interval folded in. */
    public function properties(ProtocolVersion $version): Properties
    {
        $base = $this->properties ?? Properties::none();

        if (!$version->hasProperties() || $this->delayInterval <= 0) {
            return $base;
        }

        return Properties::of(
            [Property::WillDelayInterval->value => $this->delayInterval] + $base->toIdentifierMap(),
            $base->userProperties(),
        );
    }
}
