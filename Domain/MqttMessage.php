<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * One application message, as received.
 *
 * THE PAYLOAD IS BYTES AND STAYS BYTES
 * ------------------------------------
 * MQTT says nothing whatsoever about payload format. It is an opaque byte
 * string: a JSON document, a protobuf, four bytes of little-endian float from a
 * temperature sensor, or a JPEG. That is the point of it in the device world,
 * and it is why this class holds {@see self::$payload} as a raw string and
 * offers {@see self::json()} as an explicitly fallible accessor rather than
 * decoding on construction.
 *
 * Decoding eagerly would be wrong in both directions: it would throw on a
 * perfectly valid binary payload, and it would quietly accept `null` from
 * `json_decode` as though the sensor had sent one.
 *
 * `$dup` DOES NOT MEAN "THIS IS A DUPLICATE"
 * -----------------------------------------
 * It means the broker is RE-DELIVERING this packet because it did not see an
 * acknowledgement. Whether the application already handled it is precisely what
 * neither end knows — if the first copy arrived and the PUBACK was lost, `dup`
 * is set and the message is genuinely a repeat; if the first copy never
 * arrived, `dup` is set and this is the only copy.
 *
 * So `dup` is a diagnostic, never a deduplication key. At QoS 1 the handler
 * must be idempotent; at QoS 2 the protocol's four-packet exchange is what
 * provides the guarantee, not this flag.
 *
 * `$retained` IS WHY A SUBSCRIBER SEES OLD NEWS
 * -------------------------------------------
 * True when this arrived because it was the retained message for its topic,
 * rather than because it had just been published. A subscriber that treats
 * every message as current will act on an hour-old reading the instant it
 * subscribes, which is usually right for a status topic and usually wrong for a
 * command topic.
 *
 * Note the interaction with {@see Subscription::$retainAsPublished}: by default
 * the broker CLEARS this flag on live messages, which is what makes it a
 * reliable signal. Turning that option on means a live message can arrive with
 * the flag set because the publisher set it, and the distinction is lost.
 */
final readonly class MqttMessage
{
    public function __construct(
        public string $topic,
        public string $payload,
        public QoS $qos = QoS::AtMostOnce,
        public bool $retained = false,
        public bool $dup = false,
        /** Present at QoS 1 and 2 only; `null` at QoS 0, where the protocol forbids one. */
        public ?int $packetId = null,
        public ?Properties $properties = null,
    ) {}

    /**
     * Decode the payload as a JSON object.
     *
     * @return array<string, mixed>|null `null` when the payload is not a JSON
     *         object — which includes valid JSON that is a scalar or a list.
     *         The caller gets one unambiguous answer to "can I treat this as
     *         the associative array the PubSubPort contract describes", and
     *         `json_decode` returning `null` for the literal input `null`
     *         cannot be mistaken for success.
     */
    public function json(): ?array
    {
        if ($this->payload === '') {
            return null;
        }

        $decoded = json_decode($this->payload, true, 512, \JSON_INVALID_UTF8_SUBSTITUTE);

        if (!\is_array($decoded) || array_is_list($decoded)) {
            return null;
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /** The properties, never null, for a caller that does not want to check. */
    public function properties(): Properties
    {
        return $this->properties ?? Properties::none();
    }

    /**
     * The MQTT 5.0 Content Type property, if the publisher set one.
     *
     * Advisory: nothing requires a publisher to set it and nothing validates
     * it against the bytes.
     */
    public function contentType(): ?string
    {
        return $this->properties()->string(Property::ContentType);
    }

    /**
     * Did the publisher declare the payload to be UTF-8 text?
     *
     * The `Payload Format Indicator` is 0 for unspecified bytes and 1 for
     * UTF-8. A broker MAY validate it and reject a mismatch with
     * `0x99 Payload format invalid`, but most do not — so this reports the
     * publisher's claim and not a verified fact.
     */
    public function declaresUtf8Payload(): bool
    {
        return $this->properties()->int(Property::PayloadFormatIndicator, 0) === 1;
    }

    /**
     * The topic a reply should go to, if the publisher asked for one.
     *
     * MQTT 5.0's request/response convention: a publisher sets `Response
     * Topic` and usually `Correlation Data`, and a responder publishes its
     * answer to that topic echoing the correlation bytes. It is a convention
     * the protocol carries rather than implements — nothing routes the reply
     * and nothing matches it up.
     */
    public function responseTopic(): ?string
    {
        return $this->properties()->string(Property::ResponseTopic);
    }

    public function correlationData(): ?string
    {
        return $this->properties()->string(Property::CorrelationData);
    }
}
