<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * One topic filter and the options byte that accompanies it.
 *
 * THE OPTIONS BYTE IS 3.1.1's QoS BYTE WITH FOUR BITS FILLED IN
 * ------------------------------------------------------------
 * In 3.1.1 each filter in a SUBSCRIBE is followed by one byte holding only the
 * requested QoS in bits 0-1; bits 2-7 are reserved and must be zero. In 5.0 the
 * same byte gained three fields:
 *
 *     bit 0-1  Maximum QoS            (3 is a Protocol Error)
 *     bit 2    No Local
 *     bit 3    Retain As Published
 *     bit 4-5  Retain Handling        (3 is a Protocol Error)
 *     bit 6-7  Reserved, must be 0
 *
 * So the same structure encodes differently per version, and setting a 5.0
 * option on a 3.1.1 subscription does not degrade — it sets a RESERVED bit,
 * which "the Server MUST treat ... as malformed", closing the connection.
 * {@see self::optionsByte()} therefore takes the version and silently drops the
 * 5.0 fields on 3.1.1, which is the one place in this plugin where quietly
 * ignoring a caller's request is right: the alternative is refusing to
 * subscribe at all against a 3.1.1 broker.
 *
 * `noLocal` IS THE ONE THAT PREVENTS A LOOP
 * ----------------------------------------
 * `No Local` tells the broker not to send this client messages this client
 * published. Without it, a process that both publishes to and subscribes on the
 * same topic receives its own messages — which for anything that republishes in
 * response is an infinite loop through the broker, at whatever rate the network
 * allows.
 *
 * It is 5.0 only, so on 3.1.1 the loop has to be broken in the application, and
 * a client that subscribes to a filter matching its own publishes should assume
 * it will see them.
 *
 * `retainHandling` CONTROLS A BURST AT SUBSCRIBE TIME
 * -------------------------------------------------
 * By default (0) the broker sends every retained message matching the filter
 * the moment the subscription is made. For `#` on a busy broker that is one
 * message per topic that has ever been retained, arriving at once, before
 * anything the application considers "live". Option 2 suppresses them, and 1
 * sends them only if the subscription is new.
 */
final readonly class Subscription
{
    /** Send retained messages at subscribe time. The default. */
    public const RETAIN_SEND_ALWAYS = 0;

    /** Send them only if this subscription did not already exist. */
    public const RETAIN_SEND_IF_NEW = 1;

    /** Never send retained messages at subscribe time. */
    public const RETAIN_SEND_NEVER = 2;

    public function __construct(
        public string $filter,
        public QoS $qos = QoS::AtMostOnce,
        /** 5.0 only: do not deliver this client its own publications. */
        public bool $noLocal = false,
        /**
         * 5.0 only: forward the retain flag as the publisher set it.
         *
         * Off by default, matching the protocol: without it the broker clears
         * the retain flag on live messages, so a subscriber can tell "this
         * arrived because it was retained" from "this just happened". Turning
         * it on loses that distinction, which is why it is opt-in.
         */
        public bool $retainAsPublished = false,
        /** 5.0 only: one of the `RETAIN_SEND_*` constants. */
        public int $retainHandling = self::RETAIN_SEND_ALWAYS,
        /** 5.0 only: an identifier the broker echoes on matching PUBLISHes. */
        public ?int $subscriptionIdentifier = null,
    ) {}

    /**
     * Validate this subscription, including the version-specific parts.
     *
     * @throws MqttException when the filter or an option could not go on the wire
     */
    public function assertValid(ProtocolVersion $version): void
    {
        Topic::assertFilter($this->filter);

        if ($this->retainHandling < 0 || $this->retainHandling > 2) {
            throw MqttException::cannotEncode(
                'retain handling must be 0, 1 or 2 and ' . $this->retainHandling . ' was given; the '
                . 'value 3 in those bits is a Protocol Error and anything wider overflows into the '
                . 'reserved bits, which a broker treats as a malformed packet',
            );
        }

        if ($this->subscriptionIdentifier !== null
            && ($this->subscriptionIdentifier < 1 || $this->subscriptionIdentifier > VarInt::MAX_VALUE)
        ) {
            throw MqttException::cannotEncode(
                'a Subscription Identifier must be between 1 and ' . VarInt::MAX_VALUE . ', and '
                . $this->subscriptionIdentifier . ' was given',
            );
        }

        if ($version->hasProperties()) {
            if ($this->noLocal && Topic::isShared($this->filter)) {
                // [MQTT-3.8.3-4] "It is a Protocol Error to set the No Local
                // bit to 1 on a Shared Subscription." Refused rather than
                // dropped, because the two settings mean contradictory things
                // and guessing which the caller wanted would be inventing
                // intent.
                throw MqttException::cannotEncode(
                    'No Local cannot be set on the shared subscription [' . $this->filter . ']: '
                    . '[MQTT-3.8.3-4] makes it a Protocol Error. A shared subscription delivers to one '
                    . 'member of a group, so "do not send me my own messages" has no well-defined '
                    . 'meaning — the broker cannot know which member published',
                );
            }

            return;
        }

        // 3.1.1: there is nowhere to put these, and the bits they would occupy
        // are reserved. Refused rather than dropped ONLY where dropping would
        // change behaviour the caller is relying on — a subscription identifier
        // is used for routing, so losing it silently would misroute messages.
        if ($this->subscriptionIdentifier !== null) {
            throw MqttException::cannotEncode(
                'a Subscription Identifier was set, but MQTT 3.1.1 has no properties to carry it. '
                . 'Routing would silently fall back to matching the topic against each filter, so this '
                . 'is refused rather than dropped. Set MQTT_VERSION=5 or remove the identifier',
            );
        }
    }

    /**
     * The options byte for $version.
     *
     * On 3.1.1 this is the QoS alone: every other bit is reserved, and a
     * non-zero reserved bit makes the whole SUBSCRIBE malformed.
     */
    public function optionsByte(ProtocolVersion $version): int
    {
        if (!$version->hasProperties()) {
            return $this->qos->value;
        }

        return $this->qos->value
            | ($this->noLocal ? 0b100 : 0)
            | ($this->retainAsPublished ? 0b1000 : 0)
            | (($this->retainHandling & 0b11) << 4);
    }

    /** Does this subscription's filter match $topic? */
    public function matches(string $topic): bool
    {
        return Topic::matches($this->filter, $topic);
    }
}
