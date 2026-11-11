<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * A single-identifier acknowledgement: PUBACK, PUBREC, PUBREL or PUBCOMP.
 *
 * All four have the same variable header — a packet identifier, then (5.0) a
 * reason code and properties — so they share one value object, with
 * {@see self::$type} saying which arrived. Four near-identical classes would
 * have to be distinguished at every use site anyway.
 *
 * THE 3.1.1 SHAPE IS SHORTER, AND THE DIFFERENCE IS LOAD-BEARING
 * --------------------------------------------------------------
 * In 3.1.1 these packets are the identifier and nothing else: a Remaining
 * Length of exactly 2. In 5.0 the reason code and property length are also
 * optional — a Remaining Length of 2 is legal there too and means "success,
 * no properties".
 *
 * So the decoder cannot require the reason code, and a missing one is
 * {@see ReasonCode::Success} rather than an error. Treating a two-byte 5.0
 * PUBACK as malformed would reject the most common form of the most common
 * packet.
 *
 * `0x10 No matching subscribers` ON A PUBACK IS A SUCCESS THAT LOST THE MESSAGE
 * ----------------------------------------------------------------------------
 * It means the broker accepted the publish and no subscription matched, so the
 * message was discarded. Not an error — there is nothing wrong — but it is the
 * answer to "why did nothing arrive", and it is below the `0x80` error boundary
 * so a caller checking only for errors will never see it. Hence
 * {@see ReasonCode::isSilentNoOp()}.
 */
final readonly class Ack
{
    public function __construct(
        public PacketType $type,
        public int $packetId,
        public ReasonCode $reasonCode,
        public Properties $properties,
    ) {}

    public function isError(): bool
    {
        return $this->reasonCode->isError();
    }

    public function reasonString(): ?string
    {
        return $this->properties->string(Property::ReasonString);
    }

    public function describe(): string
    {
        return $this->type->label() . ' id=' . $this->packetId
            . ' ' . $this->reasonCode->describe($this->type);
    }
}
