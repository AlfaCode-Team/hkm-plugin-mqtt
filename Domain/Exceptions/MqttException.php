<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain\Exceptions;

/**
 * Everything this client refuses or loses, with one flag that matters.
 *
 * WHY `connectionLost` IS A PROPERTY AND NOT A SUBCLASS
 * ----------------------------------------------------
 * The caller only ever asks one question: may I keep using this connection, or
 * must I throw it away and dial again? MQTT answers that itself, and more
 * sharply than most protocols — the specification names a class of
 * "Malformed Packet" and "Protocol Error" conditions after which the receiver
 * MUST close the Network Connection, while a SUBACK carrying
 * `0x8F Topic Filter invalid` leaves the session perfectly usable.
 *
 * A reconnect loop that cannot tell those apart either hammers a broker that is
 * refusing it, or throws away a healthy session over one bad filter.
 *
 * So the distinction is data on the exception, not a hierarchy every catch site
 * has to enumerate.
 *
 * NON-TEXT BYTES ARE ESCAPED OUT OF EVERY MESSAGE
 * -----------------------------------------------
 * {@see self::printable()} is applied to anything that came from outside.
 *
 * MQTT is binary and length-prefixed, so a topic cannot append a command the
 * way a NATS subject can — but it reaches a LOG FILE, which is text, and there
 * the old injection is waiting: a topic containing CRLF forges log lines, and a
 * topic containing control bytes or a stray escape sequence can rewrite a
 * terminal. The specification positively permits most of this — only U+0000 is
 * forbidden outright [MQTT-1.5.4-2], while U+0001..U+001F and U+007F..U+009F
 * are merely SHOULD NOT — so a well-behaved broker will hand this client a
 * topic full of control characters without complaint.
 *
 * The attacker-controlled value is the one thing in the message that must not
 * be trusted to be text.
 */
final class MqttException extends \RuntimeException
{
    private function __construct(
        string $message,
        public readonly bool $connectionLost = false,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * A topic name this client will not publish to.
     *
     * The connection is untouched: nothing was written, which is the whole
     * point of validating before encoding.
     */
    public static function invalidTopic(string $topic, string $reason): self
    {
        return new self(
            'Refusing the MQTT topic name [' . self::printable($topic) . "] because {$reason}. "
            . 'Nothing was written.',
            connectionLost: false,
        );
    }

    /** A subscription filter (which may use wildcards) that is still not usable. */
    public static function invalidFilter(string $filter, string $reason): self
    {
        return new self(
            'Refusing the MQTT topic filter [' . self::printable($filter) . "] because {$reason}. "
            . 'Nothing was written.',
            connectionLost: false,
        );
    }

    /**
     * A string that cannot be put in an MQTT UTF-8 Encoded String field.
     *
     * Worth refusing locally rather than letting the broker do it: the broker's
     * remedy for a malformed string is to close the connection, so one bad
     * client id or user property takes down every subscription on the link.
     */
    public static function invalidString(string $field, string $reason): self
    {
        return new self(
            "Refusing to encode {$field} because {$reason}. An MQTT UTF-8 Encoded String must be "
            . 'well-formed UTF-8, must not contain U+0000, and must not exceed 65,535 bytes; a receiver '
            . 'treats a violation as a Malformed Packet and closes the connection, which would take '
            . 'every subscription on this link with it. Nothing was written.',
            connectionLost: false,
        );
    }

    /**
     * The packet on the wire is not decodable.
     *
     * ALWAYS `connectionLost`. This is not a judgement call: the specification
     * requires the receiver of a Malformed Packet to close the Network
     * Connection, and the practical reason is that a length-prefixed stream
     * offers no way to resynchronise. Having mis-read one length, this client
     * no longer knows where the next packet begins — so every subsequent byte
     * is nonsense, and "skip it and carry on" means reading payload bytes as
     * packet headers for the rest of the connection's life.
     */
    public static function malformedPacket(string $reason): self
    {
        return new self(
            "Malformed MQTT packet: {$reason}. The connection is unusable — after mis-reading one "
            . 'length there is no way to find the start of the next packet — so it is being closed.',
            connectionLost: true,
        );
    }

    /** A packet this client will not send because it would be malformed. */
    public static function cannotEncode(string $reason): self
    {
        return new self(
            "Refusing to encode an MQTT packet: {$reason}. Nothing was written.",
            connectionLost: false,
        );
    }

    public static function connectFailed(string $target, string $reason): self
    {
        return new self(
            "Could not connect to the MQTT broker at {$target}: {$reason}",
            connectionLost: true,
        );
    }

    public static function connectionLost(string $reason): self
    {
        return new self(
            "The MQTT connection is gone: {$reason}",
            connectionLost: true,
        );
    }

    /**
     * An operation was attempted with no socket.
     *
     * `connectionLost` is true so a caller's reconnect logic treats it the same
     * as a connection that died mid-use — which is what it is, from the
     * caller's point of view.
     */
    public static function notConnected(string $attempted): self
    {
        return new self(
            "Cannot {$attempted}: this MQTT connection is not open.",
            connectionLost: true,
        );
    }

    /**
     * The TLS handshake failed.
     *
     * Distinct from {@see self::connectFailed()} because the remedies have
     * nothing in common: a TCP failure is a wrong address or a firewall, and
     * this is a trust problem — a private CA, an expired certificate, or a
     * hostname that does not match. Conflating them sends an operator to check
     * the wrong thing.
     */
    public static function tlsRefused(string $reason): self
    {
        return new self($reason, connectionLost: true);
    }

    /**
     * CONNACK said no.
     *
     * The broker has already closed the connection by the time this is thrown
     * — the specification requires it to after sending a CONNACK with a
     * non-zero Reason Code — so there is nothing left to tidy up, and a
     * reconnect will be refused the same way until the cause is fixed.
     */
    public static function connectRefused(int $reasonCode, string $meaning, string $detail = ''): self
    {
        return new self(
            'The MQTT broker refused the connection: ' . $meaning
            . ' (Reason Code 0x' . strtoupper(str_pad(dechex($reasonCode), 2, '0', \STR_PAD_LEFT)) . ')'
            . ($detail !== '' ? ' — ' . self::printable($detail) : '')
            . '. The broker has already closed the connection.',
            connectionLost: true,
        );
    }

    /**
     * The broker sent DISCONNECT.
     *
     * MQTT 5.0 only — in 3.1.1 a broker that wants rid of a client simply
     * closes the socket, which is why this client cannot tell a 3.1.1 eviction
     * from a network failure and says so.
     *
     * `0x8E Session taken over` is the one every deployment eventually meets,
     * and it is not a network problem: another process connected with the same
     * Client Identifier. See {@see \Plugins\Mqtt\Domain\ClientOptions} for why
     * that is the default-unsafe setting of the whole protocol.
     */
    public static function serverDisconnected(int $reasonCode, string $meaning, string $detail = ''): self
    {
        return new self(
            'The MQTT broker sent DISCONNECT: ' . $meaning
            . ' (Reason Code 0x' . strtoupper(str_pad(dechex($reasonCode), 2, '0', \STR_PAD_LEFT)) . ')'
            . ($detail !== '' ? ' — ' . self::printable($detail) : '')
            . ($reasonCode === 0x8E
                ? '. This is NOT a network fault: another connection presented the same Client '
                  . 'Identifier, and the specification requires the broker to evict the older one. Two '
                  . 'processes are sharing one id — give each process its own.'
                : ''),
            connectionLost: true,
        );
    }

    /**
     * The handshake did not complete.
     *
     * Unlike NATS, MQTT's handshake cannot silently succeed: CONNACK is
     * mandatory and carries a reason code, so a wrong password is reported
     * rather than inferred. What DOES go wrong here is subtler — a broker that
     * sends nothing at all, which is what a TLS-only listener does when a
     * client speaks plaintext to it.
     */
    public static function handshakeFailed(string $reason): self
    {
        return new self(
            "The MQTT handshake did not complete: {$reason}",
            connectionLost: true,
        );
    }

    /** A SUBSCRIBE whose SUBACK refused one or more filters. */
    public static function subscribeRefused(string $detail): self
    {
        return new self(
            "The MQTT broker refused a subscription: {$detail}. The connection is still usable, but "
            . 'nothing will arrive on the refused filters — so a subscriber that ignored this would '
            . 'look exactly like a system in which nothing is happening.',
            connectionLost: false,
        );
    }

    public static function timedOut(string $what, float $seconds): self
    {
        return new self(
            "Timed out after {$seconds}s waiting for {$what}.",
            connectionLost: true,
        );
    }

    /**
     * Render untrusted bytes safely for a log line.
     *
     * Everything outside printable ASCII becomes `\xNN`. That is deliberately
     * aggressive — it mangles legitimate multi-byte UTF-8 topics, which MQTT
     * permits — and it is the right trade for an error path: the reader needs
     * to know which bytes were there, and the log file must not be forgeable by
     * the value being reported. The unmangled value is still on the wire for
     * anyone debugging with a packet capture.
     */
    public static function printable(string $raw, int $max = 200): string
    {
        $cut = \strlen($raw) > $max ? substr($raw, 0, $max) . '…' : $raw;

        return (string) preg_replace_callback(
            '/[^\x20-\x7E]/',
            static fn (array $m): string => '\x' . strtoupper(bin2hex($m[0])),
            $cut,
        );
    }
}
