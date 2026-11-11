<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * Whether to wrap the connection in TLS — and why MQTT cannot be stripped.
 *
 * THE INTERESTING DIFFERENCE FROM THE NATS PLUGIN
 * ----------------------------------------------
 * The NATS client's equivalent enum carries a warning: NATS negotiates TLS in
 * the clear, the server's `INFO` arrives unauthenticated, and its
 * `tls_required` flag is therefore an instruction an attacker on the path can
 * clear. The client then continues in plaintext, sends its password, and
 * reports a healthy connection. That is TLS stripping, the same bug as SMTP
 * `STARTTLS` stripping, and it is why `Auto` there is only correct on a trusted
 * hop.
 *
 * **MQTT has no in-band TLS negotiation at all.** There is no `STARTTLS`, no
 * capability exchange, no server greeting — the client speaks first, with
 * CONNECT, and either the socket was already TLS or it was not. So the decision
 * is made entirely from local configuration before a byte is sent, and there is
 * nothing on the wire for an attacker to rewrite.
 *
 * That makes {@see self::Auto} genuinely safe here, which it is not there. The
 * failure mode of pointing a plaintext client at a TLS listener is loud: the
 * broker sees a CONNECT where it expected a ClientHello and closes the socket.
 * A silent downgrade is not reachable.
 *
 * WHAT `Auto` ACTUALLY READS
 * -------------------------
 * The scheme and the port, in that order: `mqtts://` or `ssl://` means TLS,
 * and so does port 8883, which is the IANA-registered secure MQTT port. A
 * bare `mqtt://host:8883` is therefore treated as TLS — the port is a stronger
 * signal than a scheme somebody typed out of habit, and the alternative is a
 * confusing connection failure.
 *
 * `Require` remains worth having for the case `Auto` cannot see: a TLS broker
 * on a non-standard port. There, `Auto` would dial plaintext and fail, and
 * `Require` states the intent in configuration instead.
 */
enum TlsMode: string
{
    /** Never wrap. A TLS-only listener then refuses us, loudly and immediately. */
    case Off = 'off';

    /**
     * Decide from the scheme and the port.
     *
     * Safe, unlike the NATS equivalent — see the enum docblock.
     */
    case Auto = 'auto';

    /**
     * Always wrap, whatever the scheme and port say.
     *
     * For a TLS broker on a port that is not 8883, where `Auto` has nothing to
     * go on.
     */
    case Require = 'require';

    /**
     * Parse a configured value, defaulting to {@see self::Auto}.
     *
     * An unrecognised value becomes `Auto` rather than `Off`, so a typo
     * (`MQTT_TLS=reqiure`) cannot silently disable encryption. It cannot
     * become `Require` either, or the same typo would break every
     * `mqtt://127.0.0.1:1883` deployment — so it lands on the documented
     * default, and `mqtt:status` is what surfaces the mistake.
     */
    public static function parse(?string $value): self
    {
        return self::tryFrom(strtolower(trim((string) $value))) ?? self::Auto;
    }

    /**
     * Should this connection be wrapped, given what the address implies?
     *
     * @param bool $addressImpliesTls `mqtts://`/`ssl://`, or port 8883
     */
    public function shouldWrap(bool $addressImpliesTls): bool
    {
        return match ($this) {
            self::Off     => false,
            self::Require => true,
            self::Auto    => $addressImpliesTls,
        };
    }
}
