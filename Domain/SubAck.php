<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * SUBACK or UNSUBACK: one reason code per filter, in order.
 *
 * THE ORDER IS THE ONLY THING TYING A CODE TO A FILTER
 * ---------------------------------------------------
 *     The order of Reason Codes in the SUBACK packet MUST match the order of
 *     Topic Filters in the SUBSCRIBE packet.
 *
 * There are no filter names in the reply — just a list of bytes. So a client
 * that subscribed to five filters and got five codes has to pair them up by
 * position, and a client that reordered its own filters between building the
 * packet and reading the reply would attribute each refusal to the wrong topic.
 * That is why {@see \Plugins\Mqtt\Application\Services\MqttClient} keeps the
 * requested filters in a list beside the packet identifier rather than in a
 * map.
 *
 * A COUNT MISMATCH IS NOT RECOVERABLE
 * -----------------------------------
 * If the broker returns a different number of codes than there were filters,
 * the positional pairing is meaningless — there is no way to tell which filter
 * each code belongs to, and the plausible guesses (truncate, pad) both produce
 * a confident wrong answer. The decoder reports the mismatch and the client
 * treats every filter as refused, which is the only safe reading: believing a
 * subscription succeeded when it did not is the failure mode this whole plugin
 * is arranged against.
 *
 * A LOWER GRANTED QoS IS A SUCCESS WORTH NOTICING
 * ----------------------------------------------
 * A broker may grant less than was asked for, and it is not an error: `0x00`
 * in a SUBACK means "granted QoS 0", so a client that requested QoS 2 and
 * received `0x00` is subscribed, at QoS 0, with no exactly-once guarantee it
 * may believe it has. {@see self::grantedQoS()} is how that is read, and
 * {@see self::downgraded()} is how it is noticed.
 */
final readonly class SubAck
{
    /**
     * @param PacketType           $type        SubAck or UnsubAck
     * @param list<ReasonCode|int> $reasonCodes raw ints for values this client
     *        does not recognise — a code outside the table is still positional
     *        information and discarding it would misalign everything after it
     * @param list<string>         $filters     what was asked for, in order, so a
     *        refusal can be reported against the filter that caused it
     */
    public function __construct(
        public PacketType $type,
        public int $packetId,
        public array $reasonCodes,
        public Properties $properties,
        public array $filters = [],
    ) {}

    /** Did every filter succeed? */
    public function isFullyGranted(): bool
    {
        foreach ($this->reasonCodes as $code) {
            if (!$code instanceof ReasonCode || $code->isError()) {
                return false;
            }
        }

        return $this->reasonCodes !== [];
    }

    /**
     * The filters that were refused, paired with why.
     *
     * @return list<array{filter: string, code: string, remedy: string}>
     */
    public function refusals(): array
    {
        $out = [];

        foreach ($this->reasonCodes as $index => $code) {
            $isError = !$code instanceof ReasonCode || $code->isError();

            if (!$isError) {
                continue;
            }

            $out[] = [
                'filter' => $this->filters[$index] ?? ('#' . ($index + 1) . ' (filter unknown)'),
                'code'   => $code instanceof ReasonCode
                    ? $code->describe($this->type)
                    : '0x' . strtoupper(str_pad(dechex($code), 2, '0', \STR_PAD_LEFT))
                      . ' (not a reason code this client knows)',
                'remedy' => $code instanceof ReasonCode ? $code->remedy() : '',
            ];
        }

        return $out;
    }

    /**
     * The QoS actually granted for the filter at $index, or `null` if refused.
     *
     * SUBACK only — an UNSUBACK's codes are not QoS levels.
     */
    public function grantedQoS(int $index): ?QoS
    {
        if ($this->type !== PacketType::SubAck) {
            return null;
        }

        $code = $this->reasonCodes[$index] ?? null;

        return $code instanceof ReasonCode ? $code->grantedQoS() : null;
    }

    /**
     * Filters granted at a LOWER QoS than requested.
     *
     * @param  list<Subscription> $requested in the same order as the filters
     * @return list<array{filter: string, asked: QoS, granted: QoS}>
     */
    public function downgraded(array $requested): array
    {
        $out = [];

        foreach ($requested as $index => $subscription) {
            $granted = $this->grantedQoS($index);

            if ($granted !== null && $granted->value < $subscription->qos->value) {
                $out[] = [
                    'filter'  => $subscription->filter,
                    'asked'   => $subscription->qos,
                    'granted' => $granted,
                ];
            }
        }

        return $out;
    }

    public function reasonString(): ?string
    {
        return $this->properties->string(Property::ReasonString);
    }
}
