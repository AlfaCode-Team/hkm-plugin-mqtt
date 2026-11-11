<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * Every MQTT 5.0 property identifier, its wire type, and where it is legal.
 *
 * TRANSCRIBED FROM TABLE 2-4, INCLUDING THE GAPS
 * ----------------------------------------------
 * The identifiers are 1..42 with holes: there is no 4, 5, 6, 7, 10, 12..16, 20,
 * 27, 29, 30 or 32. The holes are load-bearing. Because the property block has
 * no per-property length field (see {@see PropertyType}), a decoder that meets
 * identifier `0x07` cannot step over it — it does not know whether one byte
 * follows or four. An enum with gaps makes that a `tryFrom()` returning `null`,
 * which is a refused packet, rather than a `match` with a plausible `default`.
 *
 * WHERE EACH ONE IS LEGAL IS PART OF THE SPECIFICATION, NOT ADVICE
 * ---------------------------------------------------------------
 * "A packet is malformed if it contains an Identifier which is not valid for
 * its packet type." So `Maximum QoS` in a PUBLISH is not a curiosity to be
 * ignored — it is a malformed packet, and the receiver's remedy is to close the
 * connection with `0x81`.
 *
 * This client therefore checks the packet type on BOTH sides:
 *
 * - decoding, so a broker sending a misplaced property is reported rather than
 *   quietly accepted into an application's message metadata;
 * - encoding, so this client cannot be the one that gets disconnected — and in
 *   particular cannot put `Will Delay Interval` anywhere but the Will
 *   properties, which is the easiest of these to get wrong because the Will
 *   properties sit INSIDE the CONNECT payload and look like CONNECT's own.
 */
enum Property: int
{
    case PayloadFormatIndicator      = 0x01;
    case MessageExpiryInterval       = 0x02;
    case ContentType                 = 0x03;
    case ResponseTopic               = 0x08;
    case CorrelationData             = 0x09;
    case SubscriptionIdentifier      = 0x0B;
    case SessionExpiryInterval       = 0x11;
    case AssignedClientIdentifier    = 0x12;
    case ServerKeepAlive             = 0x13;
    case AuthenticationMethod        = 0x15;
    case AuthenticationData          = 0x16;
    case RequestProblemInformation   = 0x17;
    case WillDelayInterval           = 0x18;
    case RequestResponseInformation  = 0x19;
    case ResponseInformation         = 0x1A;
    case ServerReference             = 0x1C;
    case ReasonString                = 0x1F;
    case ReceiveMaximum              = 0x21;
    case TopicAliasMaximum           = 0x22;
    case TopicAlias                  = 0x23;
    case MaximumQoS                  = 0x24;
    case RetainAvailable             = 0x25;
    case UserProperty                = 0x26;
    case MaximumPacketSize           = 0x27;
    case WildcardSubscriptionAvailable    = 0x28;
    case SubscriptionIdentifierAvailable  = 0x29;
    case SharedSubscriptionAvailable      = 0x2A;

    public function type(): PropertyType
    {
        return match ($this) {
            self::PayloadFormatIndicator,
            self::RequestProblemInformation,
            self::RequestResponseInformation,
            self::MaximumQoS,
            self::RetainAvailable,
            self::WildcardSubscriptionAvailable,
            self::SubscriptionIdentifierAvailable,
            self::SharedSubscriptionAvailable      => PropertyType::Byte,

            self::ServerKeepAlive,
            self::ReceiveMaximum,
            self::TopicAliasMaximum,
            self::TopicAlias                       => PropertyType::TwoByteInteger,

            self::MessageExpiryInterval,
            self::SessionExpiryInterval,
            self::WillDelayInterval,
            self::MaximumPacketSize                => PropertyType::FourByteInteger,

            self::SubscriptionIdentifier           => PropertyType::VariableByteInteger,

            self::ContentType,
            self::ResponseTopic,
            self::AssignedClientIdentifier,
            self::AuthenticationMethod,
            self::ResponseInformation,
            self::ServerReference,
            self::ReasonString                     => PropertyType::Utf8String,

            self::CorrelationData,
            self::AuthenticationData               => PropertyType::BinaryData,

            self::UserProperty                     => PropertyType::Utf8StringPair,
        };
    }

    /**
     * The packet types this property may appear in.
     *
     * Will properties are NOT a packet type and are reported by
     * {@see self::allowedInWill()} instead — they are a nested block inside the
     * CONNECT payload, and conflating the two is how `Will Delay Interval` ends
     * up in CONNECT's own property block, where it is malformed.
     *
     * @return list<PacketType>
     */
    public function allowedIn(): array
    {
        return match ($this) {
            self::PayloadFormatIndicator,
            self::MessageExpiryInterval,
            self::ContentType,
            self::ResponseTopic,
            self::CorrelationData          => [PacketType::Publish],

            self::TopicAlias               => [PacketType::Publish],

            self::SubscriptionIdentifier   => [PacketType::Publish, PacketType::Subscribe],

            self::SessionExpiryInterval    => [
                PacketType::Connect, PacketType::ConnAck, PacketType::Disconnect,
            ],

            self::AssignedClientIdentifier,
            self::ServerKeepAlive,
            self::ResponseInformation,
            self::MaximumQoS,
            self::RetainAvailable,
            self::WildcardSubscriptionAvailable,
            self::SubscriptionIdentifierAvailable,
            self::SharedSubscriptionAvailable => [PacketType::ConnAck],

            self::AuthenticationMethod,
            self::AuthenticationData       => [
                PacketType::Connect, PacketType::ConnAck, PacketType::Auth,
            ],

            self::RequestProblemInformation,
            self::RequestResponseInformation => [PacketType::Connect],

            self::WillDelayInterval        => [],

            self::ServerReference          => [PacketType::ConnAck, PacketType::Disconnect],

            self::ReceiveMaximum,
            self::TopicAliasMaximum,
            self::MaximumPacketSize        => [PacketType::Connect, PacketType::ConnAck],

            self::ReasonString             => [
                PacketType::ConnAck, PacketType::PubAck, PacketType::PubRec, PacketType::PubRel,
                PacketType::PubComp, PacketType::SubAck, PacketType::UnsubAck,
                PacketType::Disconnect, PacketType::Auth,
            ],

            self::UserProperty             => [
                PacketType::Connect, PacketType::ConnAck, PacketType::Publish, PacketType::PubAck,
                PacketType::PubRec, PacketType::PubRel, PacketType::PubComp, PacketType::Subscribe,
                PacketType::SubAck, PacketType::Unsubscribe, PacketType::UnsubAck,
                PacketType::Disconnect, PacketType::Auth,
            ],
        };
    }

    /** May this property appear in the Will Properties block? */
    public function allowedInWill(): bool
    {
        return match ($this) {
            self::PayloadFormatIndicator,
            self::MessageExpiryInterval,
            self::ContentType,
            self::ResponseTopic,
            self::CorrelationData,
            self::WillDelayInterval,
            self::UserProperty => true,
            default            => false,
        };
    }

    public function isAllowedIn(PacketType $type): bool
    {
        return \in_array($type, $this->allowedIn(), true);
    }

    /**
     * May this property legitimately appear more than once in $type?
     *
     * Two properties may, and the second is easy to miss because it depends on
     * the packet:
     *
     * - **User Property**, always. It is an ordered sequence of name/value
     *   pairs and names may repeat.
     *
     * - **Subscription Identifier, in a PUBLISH only.** §3.3.2.3.8: "Multiple
     *   Subscription Identifiers will be included if the publication is the
     *   result of a match to more than one subscription." That is how a broker
     *   sending ONE copy of a message tells a client which of its
     *   subscriptions matched. In a SUBSCRIBE the same property is
     *   single-valued and §3.8.2.1.2 makes repeating it a Protocol Error.
     *
     * Getting the second one wrong is not a nicety: a flat "only User Property
     * repeats" rule rejects a conforming broker's PUBLISH as malformed and
     * closes the connection, and it does so only for clients with overlapping
     * subscriptions — so it would pass every test that did not have two.
     *
     * Every other property's own section says "It is a Protocol Error to
     * include the ... more than once", and the reason to enforce that is that a
     * duplicate is how a sender smuggles a second, different value past a
     * receiver that keeps whichever it saw first — or last, and the two
     * receivers disagreeing is the bug.
     */
    public function isRepeatable(PacketType $type): bool
    {
        return match ($this) {
            self::UserProperty           => true,
            self::SubscriptionIdentifier => $type === PacketType::Publish,
            default                      => false,
        };
    }

    public function label(): string
    {
        // Derived from the case name rather than a second hand-written table:
        // 27 names written twice is 27 chances for the two to drift, and the
        // only consumer is a log line.
        //
        // Two patterns, not one: splitting before every capital would render
        // `MaximumQoS` as "Maximum Qo S". The first breaks lower-then-upper,
        // the second breaks a run of capitals before a final capitalised word,
        // which leaves acronyms such as QoS intact.
        return trim((string) preg_replace(
            ['/([a-z0-9])([A-Z])/', '/([A-Z]+)([A-Z][a-z])/'],
            '$1 $2',
            $this->name,
        ));
    }
}
