<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Infrastructure\Adapters;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\TlsMode;
use Plugins\Mqtt\Domain\Will;
use Plugins\Mqtt\Infrastructure\Transport\StreamConnection;

/**
 * Builds the adapter from the environment. The one place `env()` is read.
 *
 * WHY THIS IS A FACTORY AND NOT A CONTAINER BINDING
 * -------------------------------------------------
 * An MQTT connection must live for the whole process, and `register()` binds
 * into the request-scoped `ModuleContainer`. Binding the client there would
 * open a TCP connection, do a TLS handshake and a CONNECT/CONNACK round trip
 * **per request** — and then throw the connection away.
 *
 * For MQTT that is worse than merely wasteful, and the reason is the client
 * identifier. A broker treats the identifier as an exclusive name and
 * `[MQTT-3.1.4-3]` requires it to DISCONNECT whoever held it before. So a
 * per-request connection sharing one configured identifier would evict the
 * long-lived subscriber on every single request — see {@see ClientId}.
 *
 * So the project binds it as a PORT, where the kernel keeps it in the
 * app-lifetime `CoreContainer`:
 *
 * ```php
 * // app/bootstrap/base.php
 * ->withPorts([
 *     PubSubPort::class => MqttFactory::fromEnv(),
 * ])
 * ```
 *
 * One connection per worker, established on the first publish, reused for every
 * request after it — and, because {@see self::clientId()} generates a distinct
 * identifier per process by default, one that cannot evict anything.
 */
final class MqttFactory
{
    private function __construct() {}

    /**
     * The adapter, configured from `MQTT_*`.
     *
     * Does NOT connect. Connecting here would make a broker outage a boot
     * failure for every project that merely has the plugin enabled — and the
     * whole point of the publish-side design is that an unreachable broker
     * costs the notification and nothing else.
     *
     * @throws MqttException on a configuration error (an unparseable URL, a bad
     *         port, a contradictory session setting) — which IS worth failing
     *         the boot for, because it can never start working on its own
     */
    public static function fromEnv(?LoggerPort $logger = null): MqttPubSub
    {
        return self::fromOptions(self::optionsFromEnv($logger), $logger);
    }

    /**
     * The adapter from options already resolved.
     *
     * Exists because {@see self::optionsFromEnv()} GENERATES a client
     * identifier, so calling it twice yields two different clients — and a
     * caller that printed the options from one call and connected with another
     * would report a configuration it is not using. `mqtt:status` did exactly
     * that until this method existed: it printed one generated id, connected
     * with a second, and then reported the difference as the broker having
     * assigned one.
     *
     * Also the seam for a project that builds {@see ClientOptions} itself — a
     * will with properties, say, which the environment cannot express.
     */
    public static function fromOptions(ClientOptions $options, ?LoggerPort $logger = null): MqttPubSub
    {
        $connection = new StreamConnection(
            addresses: $options->addresses,
            tlsMode: $options->tls,
            connectTimeout: $options->connectTimeout,
            tlsCa: $options->tlsCa,
            tlsVerify: !$options->tlsInsecure,
        );

        return new MqttPubSub(
            client: new MqttClient($connection, $options, $logger),
            options: $options,
            logger: $logger,
        );
    }

    /**
     * A standalone client, for a CLI command.
     *
     * Separate from {@see self::fromEnv()} because a command wants the native
     * surface — QoS 1 and 2, retained messages, wills, the MQTT 5.0 properties
     * — and wants to see failures as exceptions rather than as the `-1` the
     * port contract requires.
     */
    public static function clientFromEnv(?LoggerPort $logger = null): MqttClient
    {
        return self::fromEnv($logger)->client();
    }

    /**
     * The resolved options, so a status command can report them without dialling.
     *
     * @throws MqttException on a configuration error
     */
    public static function optionsFromEnv(?LoggerPort $logger = null): ClientOptions
    {
        $addresses = ServerAddress::parseList(self::text(env('MQTT_URL'), 'mqtt://127.0.0.1:1883'));
        $first     = $addresses[0];

        // `mqtts://` in the URL is an explicit instruction and outranks the
        // mode, which may still be sitting at its `auto` default.
        $mode = TlsMode::parse(self::text(env('MQTT_TLS'), ''));

        if ($first->tls && $mode !== TlsMode::Off) {
            $mode = TlsMode::Require;
        }

        $insecure = self::flag(env('MQTT_TLS_INSECURE'), false);

        if ($insecure) {
            $logger?->warning('mqtt.tls.verification_disabled', [
                'effect' => 'MQTT_TLS_INSECURE=true accepts ANY certificate, so the connection is '
                    . 'encrypted against a passive observer and wide open to an active one — an '
                    . 'interceptor presents its own certificate and is accepted. Use MQTT_TLS_CA with '
                    . 'the private CA bundle instead.',
            ]);
        }

        $rawVersion = self::text(env('MQTT_VERSION'), '5');
        $version    = ProtocolVersion::parse($rawVersion);

        if ($version === null) {
            // Refused rather than defaulted. The wire format differs between
            // the versions, so a typo silently choosing one would produce a
            // handshake failure with no hint that the version was the cause.
            throw MqttException::cannotEncode(
                'MQTT_VERSION is [' . MqttException::printable($rawVersion) . '], which is not a '
                . 'version this client speaks. Use 5 (the default) or 3.1.1',
            );
        }

        $clientId = self::clientId($logger);

        return ClientOptions::create(
            addresses: $addresses,
            clientId: $clientId,
            // Credentials in the URL win over the separate variables, because
            // somebody who wrote them into the URL has said where the truth is,
            // and silently preferring the env var would make the URL's
            // credentials dead configuration that still looks live.
            user: $first->user !== '' ? $first->user : self::text(env('MQTT_USER'), ''),
            pass: $first->pass !== '' ? $first->pass : self::text(env('MQTT_PASS'), ''),
            version: $version,
            keepAlive: self::count(env('MQTT_KEEP_ALIVE'), 60),
            cleanStart: self::flag(env('MQTT_CLEAN_START'), true),
            sessionExpiry: self::count(env('MQTT_SESSION_EXPIRY'), 0),
            will: self::will(),
            tls: $mode,
            tlsCa: self::text(env('MQTT_TLS_CA'), ''),
            tlsInsecure: $insecure,
            connectTimeout: self::seconds(env('MQTT_CONNECT_TIMEOUT'), 5.0),
            readTimeout: self::seconds(env('MQTT_READ_TIMEOUT'), 5.0),
            maxPacketBytes: self::count(env('MQTT_MAX_PACKET_BYTES'), 8388608),
            maxReconnects: self::count(env('MQTT_MAX_RECONNECTS'), 10),
            reconnectWait: self::seconds(env('MQTT_RECONNECT_WAIT'), 2.0),
            failureCooldown: self::seconds(env('MQTT_FAILURE_COOLDOWN'), 30.0),
            defaultQos: self::qos(env('MQTT_QOS')),
            defaultRetain: self::flag(env('MQTT_RETAIN'), false),
            topicPrefix: self::text(env('MQTT_TOPIC_PREFIX'), ''),
            // The separator is read WITHOUT a default-if-empty, because empty is
            // a meaningful setting here: it disables translation. Passing it
            // through self::text() with a '.' default would make
            // `MQTT_TOPIC_SEPARATOR=` mean the opposite of what it says.
            topicSeparator: self::separator(env('MQTT_TOPIC_SEPARATOR')),
            shareName: self::text(env('MQTT_SHARE_NAME'), ''),
        );
    }

    /**
     * The client identifier, generated per process unless one is configured.
     *
     * THE WARNING IS THE POINT. A configured identifier is shared by every
     * process that reads the same `.env`, and the broker resolves that sharing
     * by disconnecting whoever held it — so a web pool plus a subscriber on one
     * identifier is two processes evicting each other indefinitely, with every
     * individual operation reporting success. See {@see ClientId} for the full
     * sequence.
     *
     * It is still permitted, because exactly one case needs it: a single
     * supervised subscriber wanting the broker to hold its session across a
     * restart, which requires the same identifier every time.
     */
    private static function clientId(?LoggerPort $logger): ClientId
    {
        $configured = self::text(env('MQTT_CLIENT_ID'), '');

        if ($configured === '') {
            return ClientId::generate(self::text(env('MQTT_CLIENT_ID_PREFIX'), 'hkm'));
        }

        $clientId = ClientId::configured($configured);

        $logger?->warning('mqtt.client_id.fixed', [
            'clientId' => $clientId->value,
            'effect'   => 'A fixed MQTT_CLIENT_ID is an exclusive name on the broker: [MQTT-3.1.4-3] '
                . 'requires the broker to DISCONNECT whoever held it when another connection presents '
                . 'it. If more than one process reads this configuration — a web pool and a '
                . 'subscriber, say — they will evict each other indefinitely while every publish and '
                . 'every connect reports success. Correct only for ONE supervised process that needs a '
                . 'persistent session; otherwise leave MQTT_CLIENT_ID unset and each process derives '
                . 'its own.',
        ]);

        $portability = $clientId->portabilityWarning();

        if ($portability !== '') {
            $logger?->warning('mqtt.client_id.portability', [
                'clientId' => $clientId->value,
                'detail'   => $portability,
            ]);
        }

        return $clientId;
    }

    /**
     * The will, when one is configured.
     *
     * `MQTT_WILL_TOPIC` alone turns it on, and the other four are read only
     * then — which is why they are declared in `config[]` without defaults and
     * written commented out. A default payload or QoS for a will that does not
     * exist is four lines of configuration describing nothing.
     *
     * A project wanting something the environment cannot express — will
     * properties, a content type, correlation data — builds {@see Will} itself
     * and passes it to {@see ClientOptions::create()}.
     */
    private static function will(): ?Will
    {
        $topic = self::text(env('MQTT_WILL_TOPIC'), '');

        if ($topic === '') {
            return null;
        }

        return new Will(
            topic: $topic,
            payload: self::text(env('MQTT_WILL_PAYLOAD'), ''),
            qos: self::qos(env('MQTT_WILL_QOS')),
            retain: self::flag(env('MQTT_WILL_RETAIN'), false),
            delayInterval: self::count(env('MQTT_WILL_DELAY'), 0),
        );
    }

    /**
     * These helpers take the VALUE, not the key, and that is on purpose.
     *
     * The obvious shape is `self::text('MQTT_URL', '…')`, with `env()` inside
     * the helper. It reads better and it blinds `ground check`: the inspector
     * looks for a literal `env('KEY')` to decide whether a declared `config[]`
     * entry is actually read, so every key would be reported as dead
     * configuration. Twenty false notes is how a real one gets ignored.
     *
     * So `env('MQTT_URL')` stays at the call site, visible, and the helpers do
     * the parsing. The checker keeps working and the behaviour is unchanged.
     *
     * `env()` and never `getenv()`: `$_ENV` is this kernel's source of truth
     * and `putenv()` is not called, so `getenv()` returns nothing for anything
     * in `.env` — a configuration that silently falls back to every default.
     */
    private static function text(mixed $value, string $default): string
    {
        $text = trim((string) ($value ?? ''));

        return $text !== '' ? $text : $default;
    }

    private static function flag(mixed $value, bool $default): bool
    {
        $text = strtolower(self::text($value, ''));

        if ($text === '') {
            return $default;
        }

        return \in_array($text, ['1', 'true', 'yes', 'on'], true);
    }

    /**
     * A positive duration, or the default.
     *
     * A zero or negative value falls back rather than being honoured: an
     * `MQTT_READ_TIMEOUT=0` would busy-spin a worker at 100% CPU, and an
     * `MQTT_CONNECT_TIMEOUT=0` would make every connect fail instantly. Both
     * are far more likely to be an empty variable or a typo than an intention.
     */
    private static function seconds(mixed $value, float $default): float
    {
        $raw = self::text($value, '');

        if ($raw === '' || !is_numeric($raw)) {
            return $default;
        }

        $seconds = (float) $raw;

        return $seconds > 0 ? $seconds : $default;
    }

    /**
     * A non-negative integer; 0 is meaningful.
     *
     * Zero disables reconnection, disables the keep-alive, and means "no
     * session expiry" — three settings where it is a real choice rather than an
     * empty variable, which is why this does not fall back on it the way
     * {@see self::seconds()} does.
     */
    private static function count(mixed $value, int $default): int
    {
        $raw = self::text($value, '');

        if ($raw === '' || !ctype_digit($raw)) {
            return $default;
        }

        return (int) $raw;
    }

    /**
     * A QoS level, defaulting to 0.
     *
     * An unrecognised value becomes 0 rather than being refused, and 0 is the
     * level `PubSubPort` promises — so a typo cannot silently buy at-least-once
     * delivery with the latency and the duplicate handling that implies.
     */
    private static function qos(mixed $value): QoS
    {
        $raw = self::text($value, '');

        if ($raw === '' || !ctype_digit($raw)) {
            return QoS::AtMostOnce;
        }

        return QoS::tryFrom((int) $raw) ?? QoS::AtMostOnce;
    }

    /**
     * The channel-name separator, where EMPTY is a real setting.
     *
     * `MQTT_TOPIC_SEPARATOR=` means "do not translate", so this cannot use
     * {@see self::text()} with a `'.'` default — that would read an explicit
     * empty value as a request for the default and do the opposite of what the
     * operator asked.
     *
     * An unset variable is a different thing from an empty one, and `env()`
     * returns `null` for the first and `''` for the second, which is the
     * distinction this method rests on.
     */
    private static function separator(mixed $value): string
    {
        if ($value === null) {
            return '.';
        }

        return trim((string) $value);
    }
}
