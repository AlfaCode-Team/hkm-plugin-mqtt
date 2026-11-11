<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * Everything the client needs, resolved and validated once.
 *
 * WHY THIS IS A VALUE OBJECT AND NOT A BAG OF CONSTRUCTOR ARGUMENTS
 * ----------------------------------------------------------------
 * Several of these settings only make sense together, and the combinations that
 * do not are worth refusing at construction rather than discovering at connect
 * time or — worse — not discovering at all:
 *
 * - `cleanStart: false` with an EMPTY client id is a contradiction. Resuming a
 *   session means naming the session to resume, and a zero-length id names
 *   nothing. MQTT 3.1.1 requires the broker to refuse the combination outright;
 *   5.0 is quieter about it and the result is still a session that can never be
 *   resumed.
 * - `cleanStart: false` with a GENERATED client id is the same mistake wearing
 *   a disguise, and it is the one that actually happens. The id is unique per
 *   process, so every start resumes nothing and leaves a session behind on the
 *   broker — and because a 5.0 session with no expiry is kept indefinitely, a
 *   process restarting hourly accumulates one abandoned session per restart,
 *   each holding its subscriptions and its queued QoS 1 messages until the
 *   broker runs out of whatever it keeps them in.
 * - `sessionExpiry` on 3.1.1 has nowhere to go: the property does not exist, so
 *   a non-zero value there is silently meaningless rather than wrong.
 *
 * None of these produce an error from a broker that a log would show, which is
 * why they are checked here.
 *
 * THE KEEP-ALIVE IS NOT A TIMEOUT, IT IS A CONTRACT
 * ------------------------------------------------
 * `keepAlive` is a promise to send SOMETHING within that many seconds, and
 * `[MQTT-3.1.2-22]` lets the broker close the connection if it hears nothing
 * for 1.5x that long. A subscriber sitting on an idle topic sends nothing at
 * all, so the PINGREQ is not housekeeping — it is the only thing keeping an
 * idle subscription alive, and a client that omits it works perfectly until the
 * topic goes quiet for a minute.
 */
final readonly class ClientOptions
{
    /**
     * @param non-empty-list<ServerAddress> $addresses tried in order
     * @param string $topicSeparator the character in a PubSubPort channel name
     *               that maps to MQTT's `/`; `''` disables translation. See
     *               {@see \Plugins\Mqtt\Infrastructure\Adapters\MqttPubSub}
     *               for why this exists at all
     */
    private function __construct(
        public array $addresses,
        public ClientId $clientId,
        public string $user,
        public string $pass,
        public ProtocolVersion $version,
        public int $keepAlive,
        public bool $cleanStart,
        public int $sessionExpiry,
        public ?Will $will,
        public TlsMode $tls,
        public string $tlsCa,
        public bool $tlsInsecure,
        public float $connectTimeout,
        public float $readTimeout,
        public int $maxPacketBytes,
        public int $maxReconnects,
        public float $reconnectWait,
        public float $failureCooldown,
        public QoS $defaultQos,
        public bool $defaultRetain,
        public string $topicPrefix,
        public string $topicSeparator,
        public string $shareName,
    ) {}

    /**
     * @param non-empty-list<ServerAddress> $addresses
     * @throws MqttException on a combination that cannot work
     */
    public static function create(
        array $addresses,
        ?ClientId $clientId = null,
        string $user = '',
        string $pass = '',
        ProtocolVersion $version = ProtocolVersion::V5,
        int $keepAlive = 60,
        bool $cleanStart = true,
        int $sessionExpiry = 0,
        ?Will $will = null,
        TlsMode $tls = TlsMode::Auto,
        string $tlsCa = '',
        bool $tlsInsecure = false,
        float $connectTimeout = 5.0,
        float $readTimeout = 5.0,
        int $maxPacketBytes = 8388608,
        int $maxReconnects = 10,
        float $reconnectWait = 2.0,
        float $failureCooldown = 30.0,
        QoS $defaultQos = QoS::AtMostOnce,
        bool $defaultRetain = false,
        string $topicPrefix = '',
        string $topicSeparator = '.',
        string $shareName = '',
    ): self {
        $clientId ??= ClientId::generate();

        // Credentials on the address win over the explicit arguments only when
        // the arguments are empty — so MQTT_USER can override a URL that has a
        // stale user baked into it, which is the direction an operator expects.
        if ($user === '' && $addresses[0]->hasCredentials()) {
            $user = $addresses[0]->user;
            $pass = $addresses[0]->pass;
        }

        if ($keepAlive < 0 || $keepAlive > 65535) {
            throw MqttException::cannotEncode(
                'the keep alive is a Two Byte Integer of seconds, so it must be 0-65535, and '
                . $keepAlive . ' was given. Zero disables the mechanism entirely, which means the '
                . 'broker will never time this connection out and a half-open socket is never noticed',
            );
        }

        if ($maxPacketBytes < 128) {
            throw MqttException::cannotEncode(
                'the maximum packet size must be at least 128 bytes and ' . $maxPacketBytes
                . ' was given; a CONNECT alone is larger than that, so the client could not handshake',
            );
        }

        if (!$cleanStart) {
            if ($clientId->isEmpty()) {
                throw MqttException::cannotEncode(
                    'a persistent session was asked for (clean start off) with an EMPTY client '
                    . 'identifier. Resuming a session means naming which session, and a zero-length id '
                    . 'names nothing — MQTT 3.1.1 requires the broker to refuse this outright with '
                    . '0x02 identifier rejected. Set MQTT_CLIENT_ID, or turn clean start on',
                );
            }

            if ($clientId->generated) {
                throw MqttException::cannotEncode(
                    'a persistent session was asked for (clean start off) with a GENERATED client '
                    . 'identifier [' . $clientId->value . ']. The id is unique to this process, so '
                    . 'there is never a session to resume — and every start leaves another abandoned '
                    . 'session on the broker holding its subscriptions and queued messages, which a '
                    . 'process that restarts regularly accumulates without limit. Either set '
                    . 'MQTT_CLIENT_ID to a stable value for this one process, or leave clean start on',
                );
            }
        }

        if ($sessionExpiry < 0) {
            throw MqttException::cannotEncode(
                'the session expiry interval cannot be negative, and ' . $sessionExpiry . ' was given',
            );
        }

        if ($shareName !== '' && !$version->hasSharedSubscriptions()) {
            throw MqttException::cannotEncode(
                'a share name [' . MqttException::printable($shareName) . '] was configured, but shared '
                . 'subscriptions are an MQTT 5.0 feature and this client is set to '
                . $version->label() . '. On 3.1.1 every subscriber receives every message, so a work '
                . 'queue needs a real queue rather than a bus. Set MQTT_VERSION=5 or clear '
                . 'MQTT_SHARE_NAME',
            );
        }

        if ($shareName !== '') {
            // Validated now rather than at subscribe time: a bad share name
            // would otherwise refuse every subscription one at a time, long
            // after the configuration that caused it was read.
            Topic::shared($shareName, 'probe');
        }

        if ($topicSeparator !== '' && \strlen($topicSeparator) !== 1) {
            throw MqttException::cannotEncode(
                'the topic separator must be exactly one character, or empty to disable translation; '
                . '[' . MqttException::printable($topicSeparator) . '] was given',
            );
        }

        if ($topicSeparator === Topic::SEPARATOR) {
            throw MqttException::cannotEncode(
                'the topic separator cannot be "/", which is MQTT\'s own level separator — translating '
                . '"/" to "/" is a no-op dressed as a setting. Leave MQTT_TOPIC_SEPARATOR empty to pass '
                . 'channel names through unchanged',
            );
        }

        if ($topicPrefix !== '') {
            // The prefix is prepended to every published topic, so an invalid
            // one breaks every publish. Checked as a filter rather than a name
            // because a prefix is not a complete topic: `events` alone is, but
            // validating `events/` as a name would reject its trailing
            // separator for no reason, since the suffix will fill it.
            $reason = Utf8::reasonInvalid($topicPrefix);

            if ($reason !== '') {
                throw MqttException::cannotEncode(
                    'the topic prefix is unusable: ' . $reason,
                );
            }

            if (
                str_contains($topicPrefix, Topic::MULTI_WILDCARD)
                || str_contains($topicPrefix, Topic::SINGLE_WILDCARD)
            ) {
                throw MqttException::cannotEncode(
                    'the topic prefix [' . MqttException::printable($topicPrefix) . '] contains a '
                    . 'wildcard. It is prepended to every PUBLISH topic, where [MQTT-4.7.1-1] forbids '
                    . 'wildcards — so this would make every publish unroutable',
                );
            }
        }

        if ($will !== null) {
            // The will topic is a publish topic and is checked by the same
            // rules. Done here so a malformed will fails at construction rather
            // than on the CONNECT, where the error arrives as a closed socket.
            Topic::assertName($will->topic);

            if ($will->delayInterval > 0 && !$version->hasProperties()) {
                throw MqttException::cannotEncode(
                    'a will delay of ' . $will->delayInterval . 's was configured, but Will Delay '
                    . 'Interval is an MQTT 5.0 property and this client is set to ' . $version->label()
                    . '. On 3.1.1 the will fires as soon as the broker notices the connection is gone',
                );
            }
        }

        return new self(
            addresses: $addresses,
            clientId: $clientId,
            user: $user,
            pass: $pass,
            version: $version,
            keepAlive: $keepAlive,
            cleanStart: $cleanStart,
            sessionExpiry: $sessionExpiry,
            will: $will,
            tls: $tls,
            tlsCa: $tlsCa,
            tlsInsecure: $tlsInsecure,
            connectTimeout: $connectTimeout,
            readTimeout: $readTimeout,
            maxPacketBytes: $maxPacketBytes,
            maxReconnects: $maxReconnects,
            reconnectWait: $reconnectWait,
            failureCooldown: $failureCooldown,
            defaultQos: $defaultQos,
            defaultRetain: $defaultRetain,
            topicPrefix: $topicPrefix,
            topicSeparator: $topicSeparator,
            shareName: $shareName,
        );
    }

    /** The first address, for status output. Never credentials. */
    public function describe(): string
    {
        $targets = array_map(static fn (ServerAddress $a): string => $a->describe(), $this->addresses);

        return implode(',', $targets);
    }

    /**
     * How long to wait for a PINGRESP before giving up on the connection.
     *
     * Half the keep-alive, floored at one second. The broker's own patience is
     * 1.5x the keep-alive, so waiting longer than that would mean this client
     * was still hoping while the broker had already closed the socket.
     */
    public function pingTimeout(): float
    {
        return max(1.0, $this->keepAlive / 2);
    }

    /**
     * When to send a PINGREQ: the keep-alive, less a margin.
     *
     * The margin matters. Sending at exactly the keep-alive leaves no room for
     * the packet to travel, so a slow link makes the broker's 1.5x deadline a
     * coin flip. 80% of the window is early enough to always arrive and late
     * enough not to chatter.
     *
     * Floored at 0.5 rather than 1.0, because a 1.0 floor would make a
     * keep-alive of 1 second have no margin at all — which a real broker
     * punished by closing the connection before the first ping went out.
     */
    public function pingInterval(): float
    {
        return $this->keepAlive <= 0 ? 0.0 : max(0.5, $this->keepAlive * 0.8);
    }
}
