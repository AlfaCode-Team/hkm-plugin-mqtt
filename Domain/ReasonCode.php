<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * The MQTT 5.0 Reason Codes, what each one means, and what to do about it.
 *
 * ONE TABLE, SIX PACKETS, AND A VALUE WHOSE NAME DEPENDS ON CONTEXT
 * ----------------------------------------------------------------
 * 5.0 replaced 3.1.1's five CONNACK return codes with a single shared table
 * used by CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBACK, UNSUBACK,
 * DISCONNECT and AUTH. `0x00` is `Success` in most of them, `Normal
 * disconnection` in a DISCONNECT and `Granted QoS 0` in a SUBACK — the same
 * byte, three meanings — so the name is a function of the packet it arrived in,
 * which is what {@see self::nameIn()} is for.
 *
 * `>= 0x80` IS THE ERROR BOUNDARY, AND IT IS THE ONLY RELIABLE ONE
 * ---------------------------------------------------------------
 * Everything below `0x80` is a success with detail; everything at or above it
 * is a failure. That split is worth leaning on because the alternative — a list
 * of known-bad values — fails open on anything this client has not heard of,
 * and a future reason code that this client treated as success would be a
 * subscription silently not working.
 *
 * Two values below the boundary are worth noticing anyway, because they are
 * successes that mean nothing happened:
 *
 * - `0x10 No matching subscribers` on a PUBACK: the broker accepted the message
 *   and no one was subscribed. The publish worked and the message is gone.
 * - `0x11 No subscription existed` on an UNSUBACK: the unsubscribe was a no-op,
 *   usually a filter spelled differently from the one subscribed, since
 *   `[MQTT-3.10.4-1]` requires a character-by-character comparison.
 *
 * WHY `remedy()` EXISTS
 * --------------------
 * Because the difference between `0x85` and `0x86` is the difference between
 * "your client id is unacceptable" and "your password is wrong", and an
 * operator reading a log at 3am should not have to open the specification to
 * learn which. The text is written for whoever has to fix the deployment, and
 * `0x8E` in particular gets the long answer, since it is the one that looks
 * like a network fault and is not.
 */
enum ReasonCode: int
{
    // ─── Success (< 0x80) ───────────────────────────────────────────────────
    case Success                    = 0x00;
    case GrantedQoS1                = 0x01;
    case GrantedQoS2                = 0x02;
    case DisconnectWithWillMessage  = 0x04;
    case NoMatchingSubscribers      = 0x10;
    case NoSubscriptionExisted      = 0x11;
    case ContinueAuthentication     = 0x18;
    case ReAuthenticate             = 0x19;

    // ─── Failure (>= 0x80) ──────────────────────────────────────────────────
    case UnspecifiedError           = 0x80;
    case MalformedPacket            = 0x81;
    case ProtocolError              = 0x82;
    case ImplementationSpecificError = 0x83;
    case UnsupportedProtocolVersion = 0x84;
    case ClientIdentifierNotValid   = 0x85;
    case BadUserNameOrPassword      = 0x86;
    case NotAuthorized              = 0x87;
    case ServerUnavailable          = 0x88;
    case ServerBusy                 = 0x89;
    case Banned                     = 0x8A;
    case ServerShuttingDown         = 0x8B;
    case BadAuthenticationMethod    = 0x8C;
    case KeepAliveTimeout           = 0x8D;
    case SessionTakenOver           = 0x8E;
    case TopicFilterInvalid         = 0x8F;
    case TopicNameInvalid           = 0x90;
    case PacketIdentifierInUse      = 0x91;
    case PacketIdentifierNotFound   = 0x92;
    case ReceiveMaximumExceeded     = 0x93;
    case TopicAliasInvalid          = 0x94;
    case PacketTooLarge             = 0x95;
    case MessageRateTooHigh         = 0x96;
    case QuotaExceeded              = 0x97;
    case AdministrativeAction       = 0x98;
    case PayloadFormatInvalid       = 0x99;
    case RetainNotSupported         = 0x9A;
    case QoSNotSupported            = 0x9B;
    case UseAnotherServer           = 0x9C;
    case ServerMoved                = 0x9D;
    case SharedSubscriptionsNotSupported = 0x9E;
    case ConnectionRateExceeded     = 0x9F;
    case MaximumConnectTime         = 0xA0;
    case SubscriptionIdentifiersNotSupported = 0xA1;
    case WildcardSubscriptionsNotSupported   = 0xA2;

    /**
     * Is this a failure?
     *
     * The `>= 0x80` boundary, not a list. See the class docblock.
     */
    public function isError(): bool
    {
        return $this->value >= 0x80;
    }

    /**
     * The name this code carries in $context.
     *
     * `0x00` and `0x01`/`0x02` are the only context-dependent ones: a SUBACK's
     * `0x00` is a granted QoS, not a bare success.
     */
    public function nameIn(PacketType $context): string
    {
        if ($context === PacketType::SubAck) {
            return match ($this) {
                self::Success     => 'Granted QoS 0',
                self::GrantedQoS1 => 'Granted QoS 1',
                self::GrantedQoS2 => 'Granted QoS 2',
                default           => $this->label(),
            };
        }

        if ($context === PacketType::Disconnect && $this === self::Success) {
            return 'Normal disconnection';
        }

        return $this->label();
    }

    /**
     * Has the peer already closed the connection by sending this?
     *
     * $context matters more than the value does. The same `0x87 Not authorized`
     * ends the connection in a CONNACK — the specification requires the broker
     * to close after a non-zero CONNACK — and leaves it perfectly usable in a
     * SUBACK, where it means "that one filter, no". A reconnect loop that
     * cannot tell those apart either dials in a tight loop against a broker
     * that is refusing it, or discards a working session over one bad filter.
     */
    public function closesConnection(PacketType $context): bool
    {
        return match ($context) {
            // Any non-zero CONNACK: "the Server MUST close the Network
            // Connection". A zero one is the handshake succeeding.
            PacketType::ConnAck => $this->isError(),

            // A DISCONNECT is the close, whatever it says.
            PacketType::Disconnect => true,

            // SUBACK, UNSUBACK and the PUBLISH acknowledgements report on one
            // operation and leave the session alone.
            default => false,
        };
    }

    /**
     * Does this mean "accepted, and nothing happened"?
     *
     * A success a caller probably wants to know about. See the class docblock.
     */
    public function isSilentNoOp(): bool
    {
        return $this === self::NoMatchingSubscribers || $this === self::NoSubscriptionExisted;
    }

    /**
     * The granted QoS when this came from a SUBACK, or `null` when refused.
     *
     * A broker MAY grant a LOWER QoS than requested, and it is not an error —
     * it is the broker telling the client what it will actually get. A
     * subscriber that asked for QoS 2 and ignored a `Granted QoS 0` would
     * believe it had exactly-once delivery when it had none.
     */
    public function grantedQoS(): ?QoS
    {
        return $this->isError() ? null : QoS::tryFrom($this->value);
    }

    /**
     * Map a 3.1.1 CONNACK return code onto this table.
     *
     * 3.1.1 has five refusal codes and 5.0 has twenty-odd, so the mapping is
     * lossy in the harmless direction: each 3.1.1 code has exactly one 5.0
     * equivalent, and the point is that one client can report both versions'
     * failures in one vocabulary instead of two.
     *
     * Returns `null` for 6..255, which `[3.2.2.3]` reserves — a 3.1.1 broker
     * returning one is not following the specification, and inventing a meaning
     * for it would be making something up.
     */
    public static function fromV311ConnAck(int $returnCode): ?self
    {
        return match ($returnCode) {
            0       => self::Success,
            1       => self::UnsupportedProtocolVersion,
            2       => self::ClientIdentifierNotValid,
            3       => self::ServerUnavailable,
            4       => self::BadUserNameOrPassword,
            5       => self::NotAuthorized,
            default => null,
        };
    }

    /** What an operator should do about it. */
    public function remedy(): string
    {
        return match ($this) {
            self::SessionTakenOver =>
                'Another connection presented the same Client Identifier, so the broker evicted this '
                . 'one — [MQTT-3.1.4-3] requires it to. This is NOT a network fault and retrying will '
                . 'produce a fight: the two processes will evict each other indefinitely, each looking '
                . 'like a flapping connection. Give every process its own id. Leave MQTT_CLIENT_ID '
                . 'unset and each process derives a unique one.',

            self::ClientIdentifierNotValid =>
                'The broker rejected the Client Identifier itself. A broker need only accept 1-23 '
                . 'characters of [0-9a-zA-Z]; anything longer or with other characters is optional, so '
                . 'shorten MQTT_CLIENT_ID_PREFIX or set MQTT_CLIENT_ID explicitly.',

            self::BadUserNameOrPassword =>
                'Check MQTT_USER and MQTT_PASS. Note that a broker requiring credentials and receiving '
                . 'none reports this too, so an empty MQTT_USER looks identical to a wrong one.',

            self::NotAuthorized =>
                'The credentials were understood and refused. This is the broker\'s access control, not '
                . 'a typo — check the user\'s permission for this topic or action on the broker.',

            self::UnsupportedProtocolVersion =>
                'The broker does not speak the version this client asked for. Set MQTT_VERSION=3.1.1 — '
                . 'plenty of brokers, nats-server among them, implement 3.1.1 only.',

            self::ServerUnavailable, self::ServerBusy, self::ConnectionRateExceeded =>
                'The broker is reachable but refusing work. Back off and retry; if it persists, the '
                . 'broker is at a connection or rate limit.',

            self::Banned =>
                'The broker has banned this client or address administratively. Retrying will not help.',

            self::UseAnotherServer, self::ServerMoved =>
                'The broker is redirecting this client. The Server Reference property carries where to, '
                . 'and this client does not follow redirects — point MQTT_URL at the new address.',

            self::KeepAliveTimeout =>
                'No packet arrived within 1.5x the keep-alive window, so the broker closed the '
                . 'connection. Either the process was blocked longer than MQTT_KEEP_ALIVE or the '
                . 'PINGREQ never went out; lower MQTT_KEEP_ALIVE only after checking the loop is not '
                . 'blocking elsewhere.',

            self::TopicNameInvalid =>
                'The broker rejected the topic name. This client validates topics before sending, so '
                . 'reaching this means the broker applies an additional restriction of its own — often '
                . 'a required prefix or a ban on leading "$".',

            self::TopicFilterInvalid =>
                'The broker rejected the subscription filter. As with topic names, this client has '
                . 'already checked the protocol rules, so this is a broker-specific restriction.',

            self::PacketTooLarge =>
                'The packet exceeded the Maximum Packet Size the broker advertised in CONNACK. Publish '
                . 'less per message, or raise the broker\'s limit.',

            self::QuotaExceeded, self::MessageRateTooHigh =>
                'The broker is throttling this client. Slow the publish rate or raise the quota.',

            self::RetainNotSupported =>
                'This broker does not store retained messages. Publish without the retain flag.',

            self::QoSNotSupported =>
                'The QoS asked for is above the Maximum QoS the broker advertised in CONNACK. Lower '
                . 'MQTT_QOS.',

            self::SharedSubscriptionsNotSupported =>
                'This broker does not implement shared subscriptions ($share/...). Without them every '
                . 'worker receives every message, so a work queue needs a real queue instead.',

            self::WildcardSubscriptionsNotSupported =>
                'This broker does not implement wildcard subscriptions. Every topic must be named '
                . 'explicitly.',

            self::SubscriptionIdentifiersNotSupported =>
                'This broker does not implement subscription identifiers; routing falls back to '
                . 'matching the topic against each filter, which this client does anyway.',

            self::MalformedPacket, self::ProtocolError =>
                'The broker says this client sent something invalid, which is a bug here rather than a '
                . 'configuration problem. The connection is gone; the bytes are worth capturing.',

            self::BadAuthenticationMethod =>
                'The broker does not support the enhanced authentication method offered. This client '
                . 'implements user name and password only, so clear any Authentication Method property.',

            self::ServerShuttingDown, self::AdministrativeAction =>
                'The broker closed this connection deliberately. Reconnect; if it is a restart, a '
                . 'backoff avoids a thundering herd.',

            self::ReceiveMaximumExceeded =>
                'This client sent more unacknowledged QoS 1/2 publishes than the broker allowed in its '
                . 'Receive Maximum. That is a flow-control bug here.',

            self::TopicAliasInvalid =>
                'A topic alias outside the range the broker allowed was used. This client does not send '
                . 'topic aliases, so this indicates a broker or proxy fault.',

            self::PayloadFormatInvalid =>
                'The payload did not match the declared Payload Format Indicator — a message marked as '
                . 'UTF-8 that is not valid UTF-8.',

            self::MaximumConnectTime =>
                'The broker caps how long one connection may last and this one reached it. Reconnecting '
                . 'is the expected response.',

            self::NoMatchingSubscribers =>
                'The publish was accepted and nobody was subscribed, so the message is gone. Not an '
                . 'error — but if a subscriber was expected, compare the topic against its filter.',

            self::NoSubscriptionExisted =>
                'The unsubscribe matched nothing. Filters are compared character by character '
                . '[MQTT-3.10.4-1], so this is usually a filter spelled differently from the one '
                . 'subscribed.',

            self::ImplementationSpecificError, self::UnspecifiedError =>
                'The broker refused without saying why. Its own log is the only place the reason exists; '
                . 'a Reason String property may carry a hint.',

            self::PacketIdentifierInUse, self::PacketIdentifierNotFound =>
                'The broker and this client disagree about which packet identifiers are in flight, '
                . 'which usually means a resumed session with stale state. Connecting with a clean '
                . 'start resolves it and discards any in-flight messages.',

            default => '',
        };
    }

    public function label(): string
    {
        // Two patterns so acronyms survive: `QoSNotSupported` must not become
        // "Qo S Not Supported".
        return trim((string) preg_replace(
            ['/([a-z0-9])([A-Z])/', '/([A-Z]+)([A-Z][a-z])/'],
            '$1 $2',
            $this->name,
        ));
    }

    /** `0x8E Session taken over`, for a log line. */
    public function describe(PacketType $context): string
    {
        return '0x' . strtoupper(str_pad(dechex($this->value), 2, '0', \STR_PAD_LEFT))
            . ' ' . $this->nameIn($context);
    }
}
