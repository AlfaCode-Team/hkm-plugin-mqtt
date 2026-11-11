<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * One MQTT broker endpoint, parsed from a URL.
 *
 * CREDENTIALS IN A URL ARE READ AND THEN NEVER REPEATED
 * ----------------------------------------------------
 * `mqtt://user:pass@host:1883` is how brokers document their connection
 * strings, so it has to work. It also means a password is now inside a string
 * that every natural instinct wants to print: in a connection error, in a
 * status line, in a log context, in an exception that reaches an error tracker.
 *
 * So the password is extracted into its own field at parse time,
 * {@see self::describe()} is built from the host and port alone, and there is no
 * `__toString()` and no getter returning the original URL. The way a credential
 * leaks is that somebody logs the convenient thing, so the convenient thing
 * does not exist.
 *
 * THE PORT IS A TLS SIGNAL AND IT OUTRANKS THE SCHEME
 * ---------------------------------------------------
 * 1883 is MQTT and 8883 is MQTT-over-TLS, both IANA-registered. A URL of
 * `mqtt://broker.example.com:8883` is almost certainly a TLS broker with the
 * scheme typed from habit — so `8883` implies TLS even under `mqtt://`,
 * because the alternative is dialling plaintext at a TLS listener and
 * reporting a connection reset.
 *
 * The reverse is not inferred: `mqtts://host:1883` is honoured as TLS. An
 * explicit secure scheme is an instruction, and silently downgrading it
 * because of the port would be exactly the mistake this design avoids
 * elsewhere.
 */
final readonly class ServerAddress
{
    public const DEFAULT_PORT = 1883;
    public const TLS_PORT     = 8883;

    private function __construct(
        public string $host,
        public int $port,
        public string $user,
        public string $pass,
        /**
         * True when the scheme or the port says TLS.
         *
         * Consulted by {@see TlsMode::shouldWrap()}. Note this is derived from
         * LOCAL configuration only — MQTT has no in-band TLS negotiation, so
         * unlike the NATS client there is nothing here an attacker could have
         * rewritten.
         */
        public bool $tls,
    ) {}

    /**
     * Parse one address.
     *
     * Accepts `mqtt://host:port`, `mqtts://host:port`, `tcp://`, `ssl://`,
     * `tls://`, `host:port` and a bare `host`. A bare host is accepted because
     * `MQTT_URL=mosquitto` inside a container network is the common case and
     * refusing it would be pedantry.
     *
     * WebSocket schemes (`ws://`, `wss://`) are refused rather than silently
     * treated as TCP. MQTT over WebSockets is a different framing — an HTTP
     * upgrade, then MQTT packets inside WebSocket frames — and this client
     * speaks the TCP form only. Accepting the scheme and dialling a raw socket
     * would produce a handshake that hangs rather than an error that names the
     * cause.
     *
     * @throws MqttException on something that cannot be dialled
     */
    public static function parse(string $url): self
    {
        $raw = trim($url);

        if ($raw === '') {
            throw MqttException::connectFailed('(empty)', 'no MQTT broker address was configured');
        }

        $secureScheme = false;

        if (preg_match('#^([a-z][a-z0-9+.-]*)://#i', $raw, $match) === 1) {
            $scheme = strtolower($match[1]);
            $raw    = substr($raw, \strlen($match[0]));

            if (\in_array($scheme, ['ws', 'wss'], true)) {
                throw MqttException::connectFailed(
                    MqttException::printable($url),
                    "the scheme [{$scheme}://] is MQTT over WebSockets, which is a different framing — "
                    . 'an HTTP upgrade and then MQTT packets inside WebSocket frames. This client speaks '
                    . 'the TCP form only, so use mqtt:// or mqtts:// and the broker\'s TCP listener '
                    . '(usually 1883 or 8883)',
                );
            }

            if (!\in_array($scheme, ['mqtt', 'mqtts', 'tcp', 'ssl', 'tls'], true)) {
                throw MqttException::connectFailed(
                    MqttException::printable($url),
                    "unknown scheme [{$scheme}://]; expected mqtt://, mqtts:// or no scheme at all",
                );
            }

            $secureScheme = \in_array($scheme, ['mqtts', 'ssl', 'tls'], true);
        }

        $user = '';
        $pass = '';

        // Rightmost @, because a password may legally contain one.
        $at = strrpos($raw, '@');

        if ($at !== false) {
            $credentials = substr($raw, 0, $at);
            $raw         = substr($raw, $at + 1);
            $colon       = strpos($credentials, ':');

            if ($colon === false) {
                // `mqtt://user@host` — a single field is a user name. MQTT has
                // no token concept, so unlike the NATS client there is no
                // ambiguity to resolve here.
                $user = rawurldecode($credentials);
            } else {
                $user = rawurldecode(substr($credentials, 0, $colon));
                $pass = rawurldecode(substr($credentials, $colon + 1));
            }
        }

        // Strip any path, query or fragment: the TCP form of MQTT has no notion
        // of a path, and a trailing slash in a copied URL must not become part
        // of the host.
        foreach (['/', '?', '#'] as $terminator) {
            $cut = strpos($raw, $terminator);

            if ($cut !== false) {
                $raw = substr($raw, 0, $cut);
            }
        }

        [$host, $port] = self::splitHostPort($raw, $url, $secureScheme);

        if ($host === '') {
            throw MqttException::connectFailed(
                MqttException::printable($url),
                'no host could be read from this address',
            );
        }

        return new self($host, $port, $user, $pass, $secureScheme || $port === self::TLS_PORT);
    }

    /**
     * Parse a comma-separated list, in order.
     *
     * @return non-empty-list<self> guaranteed by the throw below, which is what
     *         lets the transport require a non-empty list rather than re-check
     * @throws MqttException when the list is empty or any entry is unusable — an
     *         entry is never skipped silently, because a typo in one host of a
     *         three-host cluster would then look like a working configuration
     *         that mysteriously never reaches that node
     */
    public static function parseList(string $urls): array
    {
        $addresses = [];

        foreach (explode(',', $urls) as $candidate) {
            if (trim($candidate) !== '') {
                $addresses[] = self::parse($candidate);
            }
        }

        if ($addresses === []) {
            throw MqttException::connectFailed('(empty)', 'no MQTT broker address was configured');
        }

        return $addresses;
    }

    /** `host:port`, with the scheme when it is TLS. Never the credentials. */
    public function describe(): string
    {
        return ($this->tls ? 'mqtts://' : 'mqtt://') . $this->endpoint();
    }

    /** The dial target. */
    public function endpoint(): string
    {
        // A literal IPv6 address has to go back inside brackets or the port
        // separator is ambiguous with the address's own colons.
        return str_contains($this->host, ':')
            ? "[{$this->host}]:{$this->port}"
            : "{$this->host}:{$this->port}";
    }

    public function hasCredentials(): bool
    {
        return $this->user !== '';
    }

    /**
     * Is the broker on this host reachable only over loopback?
     *
     * Used by `mqtt:status` to decide whether an unencrypted connection is
     * worth warning about: plaintext to 127.0.0.1 is ordinary, plaintext
     * across a network is a password on the wire.
     */
    public function isLoopback(): bool
    {
        $host = strtolower($this->host);

        return $host === 'localhost'
            || $host === '::1'
            || str_starts_with($host, '127.');
    }

    /**
     * @return array{string, int}
     * @throws MqttException
     */
    private static function splitHostPort(string $raw, string $original, bool $secureScheme): array
    {
        $default = $secureScheme ? self::TLS_PORT : self::DEFAULT_PORT;

        // Bracketed IPv6: [::1]:1883
        if (str_starts_with($raw, '[')) {
            $end = strpos($raw, ']');

            if ($end === false) {
                throw MqttException::connectFailed(
                    MqttException::printable($original),
                    'a bracketed IPv6 address was not closed',
                );
            }

            $host = substr($raw, 1, $end - 1);
            $rest = ltrim(substr($raw, $end + 1), ':');

            return [$host, $rest === '' ? $default : self::port($rest, $original)];
        }

        $colon = strrpos($raw, ':');

        if ($colon === false) {
            return [$raw, $default];
        }

        // More than one colon and no brackets: a bare IPv6 address. There is no
        // port here, because `::1:1883` is a valid address in its own right and
        // guessing which colon is the separator is how a client ends up
        // dialling a host that does not exist.
        if (substr_count($raw, ':') > 1) {
            return [$raw, $default];
        }

        $portPart = substr($raw, $colon + 1);

        return [
            substr($raw, 0, $colon),
            $portPart === '' ? $default : self::port($portPart, $original),
        ];
    }

    /** @throws MqttException */
    private static function port(string $raw, string $original): int
    {
        if (!ctype_digit($raw)) {
            throw MqttException::connectFailed(
                MqttException::printable($original),
                'the port [' . MqttException::printable($raw) . '] is not a number',
            );
        }

        $port = (int) $raw;

        if ($port < 1 || $port > 65535) {
            throw MqttException::connectFailed(
                MqttException::printable($original),
                "the port {$port} is outside 1-65535",
            );
        }

        return $port;
    }
}
