<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * The Client Identifier — the single most dangerous default in MQTT.
 *
 * WHAT THE PROTOCOL DOES WITH A DUPLICATE
 * ---------------------------------------
 *     [MQTT-3.1.4-3] If the ClientID represents a Client already connected to
 *                    the Server, the Server sends a DISCONNECT packet to the
 *                    existing Client with Reason Code 0x8E (Session taken
 *                    over) ... and MUST close the Network Connection of the
 *                    existing Client.
 *
 * Read that as an operational fact rather than a rule: **the client identifier
 * is an exclusive lock on a broker-wide name, and connecting steals it.** There
 * is no error for the new connection. It succeeds. The previous holder is
 * evicted.
 *
 * THE FAILURE THIS CAUSES, WHICH IS THE ONE THIS WORKSPACE KEEPS MEETING
 * ---------------------------------------------------------------------
 * Set `MQTT_CLIENT_ID=hkm` — the obvious thing, and what every broker's
 * quickstart shows — and deploy a realtime server plus a PHP-FPM pool:
 *
 * 1. The realtime server connects as `hkm` and subscribes. Everything works.
 * 2. An HTTP request arrives. Its worker connects as `hkm` to publish.
 * 3. The broker evicts the realtime server, which loses its subscriptions.
 * 4. The publish succeeds. The HTTP response is 200. Nothing is logged.
 * 5. The realtime server reconnects — and evicts the next publisher.
 *
 * The result is two processes fighting over one name, each reconnecting
 * constantly, with messages delivered or dropped depending on who happened to
 * hold the lock. Every individual operation reports success. Under one worker
 * in development the window is small enough to miss entirely.
 *
 * This is the same class of bug as using a queue for fan-out, which
 * {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort} documents at
 * length: it works in development, it reproduces only under concurrency, and
 * nothing anywhere reports an error.
 *
 * SO THE DEFAULT IS GENERATED, AND A FIXED ONE IS WARNED ABOUT
 * -----------------------------------------------------------
 * {@see self::generate()} is what the factory uses when `MQTT_CLIENT_ID` is
 * unset: a per-process identifier that cannot collide. Setting the variable is
 * supported, because exactly one case needs it — a single supervised subscriber
 * that wants the broker to hold its session and queued QoS 1 messages across a
 * restart, which requires the same id every time. That case is real, it is one
 * process, and `mqtt:status` warns whenever a fixed id is configured, because
 * the cost of the warning is a line of output and the cost of silence is the
 * five steps above.
 *
 * THE 23-CHARACTER CEILING IS NOT ARBITRARY
 * -----------------------------------------
 *     [MQTT-3.1.3-5] The Server MUST allow ClientIDs which are between 1 and
 *                    23 UTF-8 encoded bytes in length, and that contain only
 *                    the characters 0-9, a-z, A-Z.
 *
 * Longer identifiers and other characters are PERMITTED but optional — a broker
 * may refuse them with `0x85 Client Identifier not valid`. So a generated id
 * stays inside the guaranteed set: 23 bytes, alphanumeric only. Note that this
 * excludes `-`, which is why the generated form runs the prefix straight into
 * the random part instead of hyphenating it.
 */
final readonly class ClientId
{
    /** The length every conforming broker must accept. */
    public const MAX_GUARANTEED_LENGTH = 23;

    /**
     * Random characters in a generated id.
     *
     * 20 base-62 characters is about 119 bits, which is far more than
     * collision-avoidance needs. The reason to spend the whole budget is that
     * there is nothing else to spend it on: the id is capped at 23 bytes
     * regardless, so any character not given to the prefix is wasted if not
     * random, and a collision is an eviction rather than an error.
     */
    public const RANDOM_LENGTH = 20;

    /** @see self::MAX_GUARANTEED_LENGTH — what is left for a prefix. */
    public const MAX_PREFIX_LENGTH = self::MAX_GUARANTEED_LENGTH - self::RANDOM_LENGTH;

    private const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    private function __construct(
        public string $value,
        /** True when this was generated per process rather than configured. */
        public bool $generated,
    ) {}

    /**
     * A per-process identifier that cannot collide with another process.
     *
     * The prefix is for a human reading the broker's client list; it is
     * sanitised to the guaranteed character set and truncated, because an
     * unusable prefix must not be able to make the whole id unusable.
     *
     * @throws \Exception when the system CSPRNG is unavailable, which must stop
     *         the process rather than fall back to something weaker — a
     *         predictable id is one another process can be made to steal
     */
    public static function generate(string $prefix = 'hkm'): self
    {
        $clean = (string) preg_replace('/[^0-9a-zA-Z]/', '', $prefix);
        $clean = substr($clean, 0, self::MAX_PREFIX_LENGTH);

        $alphabet = self::ALPHABET;
        $size     = \strlen($alphabet);
        $random   = '';

        // random_int per character rather than bin2hex(random_bytes()): hex
        // spends 4 bits per character where base 62 spends 5.95, and the whole
        // budget here is 20 characters. Uniform by construction, since
        // random_int is unbiased over the range.
        for ($i = 0; $i < self::RANDOM_LENGTH; $i++) {
            $random .= $alphabet[random_int(0, $size - 1)];
        }

        return new self($clean . $random, generated: true);
    }

    /**
     * Use an identifier the operator configured.
     *
     * Validated but NOT truncated or rewritten. A broker may well accept a
     * 40-character id, and silently shortening one would produce a different
     * client than the operator named — which for a persistent session means
     * connecting to the wrong session, and for a broker ACL means failing
     * authorisation for reasons nothing explains.
     *
     * @throws MqttException when the identifier could not go on the wire at all
     */
    public static function configured(string $value): self
    {
        if ($value === '') {
            throw MqttException::cannotEncode(
                'an empty Client Identifier was configured. An empty id is legal on the wire, but it '
                . 'asks the broker to assign one — which is a different thing and is reached by '
                . 'ClientId::assignedByBroker(), not by configuring a blank value. Leave '
                . 'MQTT_CLIENT_ID unset to get a generated per-process id instead',
            );
        }

        $reason = Utf8::reasonInvalid($value);

        if ($reason !== '') {
            throw MqttException::invalidString('the Client Identifier', $reason);
        }

        return new self($value, generated: false);
    }

    /**
     * The empty identifier, asking the broker to assign one.
     *
     * Legal, and occasionally the right answer for a short-lived publisher: the
     * broker invents a unique id, so nothing can be evicted. Two costs make it
     * the non-default.
     *
     * First, this client no longer knows what it is called, so the broker's
     * client list and its own logs cannot be lined up. In MQTT 5.0 the
     * `Assigned Client Identifier` property in CONNACK closes that gap, and
     * {@see \Plugins\Mqtt\Application\Services\MqttClient} records it; in
     * 3.1.1 there is no such property and the id is simply unknowable.
     *
     * Second, the broker MAY refuse an empty id outright, and in 3.1.1 it MUST
     * refuse one combined with `CleanSession = 0` — a zero-length id cannot
     * name a session to resume, so the two settings contradict each other.
     */
    public static function assignedByBroker(): self
    {
        return new self('', generated: true);
    }

    public function isEmpty(): bool
    {
        return $this->value === '';
    }

    /**
     * Is this inside the set every conforming broker must accept?
     *
     * False does not mean invalid — see the class docblock — it means the
     * broker is within its rights to refuse it with `0x85`.
     */
    public function isGuaranteedAcceptable(): bool
    {
        return $this->value !== ''
            && \strlen($this->value) <= self::MAX_GUARANTEED_LENGTH
            && preg_match('/^[0-9a-zA-Z]+$/', $this->value) === 1;
    }

    /**
     * Why a broker might refuse this, or `''` when nothing would.
     *
     * Reported by `mqtt:status` rather than enforced, because "might refuse" is
     * the honest strength of the claim and refusing locally would break every
     * deployment whose broker is more permissive than the floor.
     */
    public function portabilityWarning(): string
    {
        if ($this->value === '') {
            return 'it is empty, so the broker assigns one — which it is also entitled to refuse, and '
                . 'in MQTT 3.1.1 MUST refuse when clean session is off, since a zero-length id cannot '
                . 'name a session to resume';
        }

        if ($this->isGuaranteedAcceptable()) {
            return '';
        }

        $problems = [];

        if (\strlen($this->value) > self::MAX_GUARANTEED_LENGTH) {
            $problems[] = 'it is ' . \strlen($this->value) . ' bytes and [MQTT-3.1.3-5] only requires a '
                . 'broker to accept up to ' . self::MAX_GUARANTEED_LENGTH;
        }

        if (preg_match('/^[0-9a-zA-Z]*$/', $this->value) !== 1) {
            $problems[] = 'it contains characters outside 0-9 a-z A-Z, which a broker need not accept';
        }

        return implode('; and ', $problems)
            . '. Most brokers are more permissive, so this is a portability note rather than a fault — '
            . 'but a broker that does refuse it answers 0x85 Client Identifier not valid';
    }

    /**
     * Should the operator be warned that this is shared across processes?
     *
     * True for any configured id. See the class docblock for what sharing one
     * costs; the warning is cheap and the failure is not.
     */
    public function risksEviction(): bool
    {
        return !$this->generated;
    }
}
