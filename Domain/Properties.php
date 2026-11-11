<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * An MQTT 5.0 property block — the bag, and the codec for it.
 *
 * THE BLOCK DOES NOT EXIST IN 3.1.1, AND THAT IS NOT A ZERO-LENGTH BLOCK
 * ---------------------------------------------------------------------
 * In 5.0 every packet with a variable header carries a property block, which is
 * a Variable Byte Integer length followed by that many bytes of entries. An
 * empty block is the single byte `0x00`.
 *
 * In 3.1.1 the block is ABSENT — there is no length byte at all. The one-byte
 * difference is the most consequential thing in this file, because a client
 * that emits `0x00` to a 3.1.1 broker has shifted every subsequent byte by one:
 * the broker reads the Client Identifier's length from the wrong place, gets a
 * nonsense length, and closes the connection as malformed. The symptom is
 * "cannot connect, no reason given", which looks like a credential problem.
 *
 * So nothing here is written unless {@see ProtocolVersion::hasProperties()},
 * and that decision is the encoder's, not this class's — see
 * {@see self::encode()}.
 *
 * WHY DECODING IS STRICT ON THREE THINGS
 * --------------------------------------
 * **An unknown identifier is fatal.** The block is TLV with no L: the
 * identifier alone determines the value's width. Identifier `0x07` does not
 * exist, so a decoder meeting it cannot know whether to skip one byte or four,
 * and skipping the wrong number means reading a value as an identifier for the
 * rest of the block. "Forward compatible, ignore what you do not know" is the
 * right instinct and is impossible here; the format did not leave room for it.
 *
 * **A misplaced identifier is fatal.** A packet "is malformed if it contains an
 * Identifier which is not valid for its packet type". `Maximum QoS` in a
 * PUBLISH is not harmless noise to be dropped — if this client accepted it, it
 * would be accepting a packet from something that is not following the
 * protocol, and passing its contents to an application as message metadata.
 *
 * **A duplicate is fatal, except User Property.** Each property's own section
 * says "It is a Protocol Error to include the ... more than once", and the
 * reason to enforce it rather than keep the last value is that "keep the first"
 * and "keep the last" are both defensible — so two implementations will choose
 * differently, and a sender can use that to make them disagree about what the
 * same bytes mean.
 *
 * USER PROPERTIES ARE A LIST, NOT A MAP
 * ------------------------------------
 * `User Property` is the one repeatable property, it is an ordered sequence of
 * name/value PAIRS, and the specification is explicit that order is preserved
 * and names may repeat. Storing them in an associative array would silently
 * drop every duplicate name and reorder the rest — so they are kept as a list
 * of pairs, and {@see self::userProperty()} exists for the common case of
 * wanting one by name while {@see self::userProperties()} keeps the truth.
 */
final class Properties
{
    /**
     * @param array<int, bool|int|string>       $values          keyed by {@see Property} value
     * @param list<array{0: string, 1: string}> $userProperties  ordered pairs
     * @param list<int>                         $subscriptionIds every Subscription
     *        Identifier on a PUBLISH — one per matching subscription, so this is
     *        a list rather than a single value. Empty for every other packet
     */
    private function __construct(
        private readonly array $values = [],
        private readonly array $userProperties = [],
        private readonly array $subscriptionIds = [],
    ) {}

    public static function none(): self
    {
        return new self();
    }

    /**
     * @param array<int, bool|int|string|null> $values keyed by `Property::X->value`
     *                      — an enum CASE cannot be an array key in PHP, keys are
     *                      int|string only, so the `->value` is not decoration.
     *                      A `null` entry is DROPPED rather than encoded, which is
     *                      what lets a caller pass a row of optional settings
     *                      straight in without filtering it first
     * @param list<array{0: string, 1: string}> $userProperties
     */
    public static function of(array $values = [], array $userProperties = []): self
    {
        $resolved = [];

        foreach ($values as $key => $value) {
            if ($value === null) {
                continue;
            }

            $property = Property::tryFrom($key);

            if ($property === null) {
                throw MqttException::cannotEncode(
                    'property identifier ' . $key . ' is not an MQTT 5.0 property',
                );
            }

            if ($property === Property::UserProperty) {
                throw MqttException::cannotEncode(
                    'User Property is repeatable and ordered, so it is passed as the second argument '
                    . 'as a list of [name, value] pairs, not as a single keyed value',
                );
            }

            $resolved[$property->value] = $value;
        }

        return new self($resolved, array_values($userProperties));
    }

    public function isEmpty(): bool
    {
        return $this->values === [] && $this->userProperties === [];
    }

    public function has(Property $property): bool
    {
        return \array_key_exists($property->value, $this->values);
    }

    public function get(Property $property): bool|int|string|null
    {
        return $this->values[$property->value] ?? null;
    }

    public function int(Property $property, ?int $default = null): ?int
    {
        $value = $this->values[$property->value] ?? null;

        return \is_int($value) ? $value : $default;
    }

    public function string(Property $property, ?string $default = null): ?string
    {
        $value = $this->values[$property->value] ?? null;

        return \is_string($value) ? $value : $default;
    }

    public function bool(Property $property, ?bool $default = null): ?bool
    {
        $value = $this->values[$property->value] ?? null;

        if (\is_bool($value)) {
            return $value;
        }

        // A Byte property is 0 or 1 on the wire; the decoder keeps it as an int
        // so an out-of-range value stays visible rather than collapsing to
        // true.
        return \is_int($value) ? $value === 1 : $default;
    }

    /** @return list<array{0: string, 1: string}> */
    public function userProperties(): array
    {
        return $this->userProperties;
    }

    /**
     * Every Subscription Identifier on this PUBLISH.
     *
     * More than one means the broker sent ONE copy of a message that matched
     * SEVERAL of this client's subscriptions, and is naming all of them —
     * §3.3.2.3.8. Empty means the broker does not use them, or this is not a
     * PUBLISH.
     *
     * @return list<int>
     */
    public function subscriptionIdentifiers(): array
    {
        return $this->subscriptionIds;
    }

    /** The LAST value for $name, or null. */
    public function userProperty(string $name): ?string
    {
        $found = null;

        foreach ($this->userProperties as [$key, $value]) {
            if ($key === $name) {
                $found = $value;
            }
        }

        return $found;
    }

    /**
     * The raw values keyed by property identifier, for composing a new bag.
     *
     * Distinct from {@see self::toArray()}, which keys by human label for logs
     * and is therefore lossy — two properties whose labels collide, or a label
     * that changes, would corrupt a round trip. This one round-trips through
     * {@see self::of()} exactly.
     *
     * @return array<int, bool|int|string>
     */
    public function toIdentifierMap(): array
    {
        return $this->values;
    }

    /** @return array<string, bool|int|string> keyed by human label, for logs and status output */
    public function toArray(): array
    {
        $out = [];

        foreach ($this->values as $id => $value) {
            $property = Property::tryFrom($id);

            if ($property !== null) {
                $out[$property->label()] = $value;
            }
        }

        foreach ($this->userProperties as [$name, $value]) {
            $out['user:' . $name] = $value;
        }

        return $out;
    }

    // ─── Codec ──────────────────────────────────────────────────────────────

    /**
     * Encode as a length-prefixed property block, or `''` for 3.1.1.
     *
     * The version is a parameter rather than a property of this object because
     * the SAME property bag is legitimately encoded for either version — a
     * caller that set a Message Expiry Interval and then connected to a 3.1.1
     * broker should lose the property, not fail. Returning `''` is what "the
     * block does not exist" means on the wire.
     *
     * @throws MqttException when a property is not legal in $type
     */
    public function encode(PacketType $type, ProtocolVersion $version, bool $will = false): string
    {
        if (!$version->hasProperties()) {
            // Not even `0x00`. See the class docblock — this one byte is the
            // difference between a working 3.1.1 connection and a broker
            // closing the socket with no explanation.
            return '';
        }

        $body = new ByteWriter();

        foreach ($this->values as $id => $value) {
            $property = Property::tryFrom($id);

            if ($property === null) {
                throw MqttException::cannotEncode('property identifier ' . $id . ' is not an MQTT 5.0 property');
            }

            $this->assertPlacement($property, $type, $will);

            $body->uint8($property->value);
            self::writeValue($body, $property, $value);
        }

        foreach ($this->userProperties as $index => $pair) {
            $this->assertPlacement(Property::UserProperty, $type, $will);

            $body->uint8(Property::UserProperty->value)
                ->utf8($pair[0], 'user property ' . $index . ' name')
                ->utf8($pair[1], 'user property ' . $index . ' value');
        }

        return VarInt::encode($body->length()) . $body->bytes();
    }

    /**
     * Read a property block from $reader.
     *
     * @throws MqttException on an unknown identifier, a misplaced one, a
     *         duplicate, or a block whose declared length does not match its
     *         contents
     */
    public static function decode(ByteReader $reader, PacketType $type, bool $will = false): self
    {
        $length = $reader->varInt('the ' . $type->label() . ' property block length');

        if ($length === 0) {
            return new self();
        }

        // A sub-reader, so a property that lies about its length cannot read
        // past the block into the fields after it — and so the leftover check
        // below is a check on THIS block rather than on the whole packet.
        $block           = $reader->slice($length, 'the ' . $type->label() . ' property block');
        $values          = [];
        $users           = [];
        $subscriptionIds = [];

        while (!$block->isExhausted()) {
            $id       = $block->uint8('a property identifier');
            $property = Property::tryFrom($id);

            if ($property === null) {
                throw MqttException::malformedPacket(
                    'property identifier 0x' . strtoupper(str_pad(dechex($id), 2, '0', \STR_PAD_LEFT))
                    . ' in ' . $type->label() . ' is not an MQTT 5.0 property. The block cannot be '
                    . 'skipped past it: there is no per-property length field, so the identifier is the '
                    . 'only thing that says how wide the value is',
                );
            }

            $allowed = $will ? $property->allowedInWill() : $property->isAllowedIn($type);

            if (!$allowed) {
                throw MqttException::malformedPacket(
                    $property->label() . ' is not valid in '
                    . ($will ? 'the Will Properties' : $type->label())
                    . ', and a packet carrying an identifier invalid for its type is malformed',
                );
            }

            if ($property === Property::UserProperty) {
                $name    = $block->utf8('a user property name');
                $users[] = [$name, $block->utf8('user property [' . $name . '] value')];

                continue;
            }

            if ($property === Property::SubscriptionIdentifier && $property->isRepeatable($type)) {
                // A PUBLISH may carry one per matching subscription, so these
                // accumulate. The FIRST is also kept in $values so the ordinary
                // single-value accessors keep working for the common case of
                // one match.
                $id              = $block->varInt($property->label());
                $subscriptionIds[] = $id;
                $values[$property->value] ??= $id;

                continue;
            }

            if (\array_key_exists($property->value, $values)) {
                throw MqttException::malformedPacket(
                    $property->label() . ' appears more than once in ' . $type->label()
                    . ', which is a Protocol Error here. The only properties that may repeat are User '
                    . 'Property, and Subscription Identifier in a PUBLISH',
                );
            }

            $values[$property->value] = self::readValue($block, $property);
        }

        return new self($values, $users, $subscriptionIds);
    }

    /** @throws MqttException */
    private function assertPlacement(Property $property, PacketType $type, bool $will): void
    {
        $allowed = $will ? $property->allowedInWill() : $property->isAllowedIn($type);

        if ($allowed) {
            return;
        }

        throw MqttException::cannotEncode(
            $property->label() . ' is not a legal property of '
            . ($will ? 'the Will Properties' : $type->label())
            . ', and a receiver treats a misplaced identifier as a Malformed Packet and closes the '
            . 'connection'
            . ($property === Property::WillDelayInterval
                ? '. Will Delay Interval belongs to the Will Properties, which are a nested block '
                  . 'inside the CONNECT payload — not to CONNECT\'s own property block'
                : ''),
        );
    }

    /** @throws MqttException */
    private static function writeValue(ByteWriter $out, Property $property, bool|int|string $value): void
    {
        $field = $property->label();

        match ($property->type()) {
            PropertyType::Byte                => $out->uint8(\is_bool($value) ? ($value ? 1 : 0) : (int) $value),
            PropertyType::TwoByteInteger      => $out->uint16((int) $value),
            PropertyType::FourByteInteger     => $out->uint32((int) $value),
            PropertyType::VariableByteInteger => $out->varInt((int) $value),
            PropertyType::Utf8String          => $out->utf8((string) $value, $field),
            PropertyType::BinaryData          => $out->binary((string) $value, $field),

            // Unreachable: User Property is the only pair type and it is
            // handled by the caller's second loop, because one identifier maps
            // to two strings and an ordered list rather than one keyed value.
            PropertyType::Utf8StringPair      => throw MqttException::cannotEncode(
                $field . ' is a string pair and must be written as a user property',
            ),
        };
    }

    /** @throws MqttException */
    private static function readValue(ByteReader $block, Property $property): int|string
    {
        $field = $property->label();

        return match ($property->type()) {
            PropertyType::Byte                => $block->uint8($field),
            PropertyType::TwoByteInteger      => $block->uint16($field),
            PropertyType::FourByteInteger     => $block->uint32($field),
            PropertyType::VariableByteInteger => $block->varInt($field),
            PropertyType::Utf8String          => $block->utf8($field),
            PropertyType::BinaryData          => $block->binary($field),
            PropertyType::Utf8StringPair      => throw MqttException::malformedPacket(
                $field . ' is a string pair and cannot be read as a single value',
            ),
        };
    }
}
