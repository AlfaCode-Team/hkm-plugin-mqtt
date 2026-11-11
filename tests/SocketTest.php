<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\TlsMode;
use Plugins\Mqtt\Infrastructure\Transport\StreamConnection;

/**
 * The real transport, over real TCP and real TLS, against a stub in a SECOND
 * PROCESS.
 *
 * WHAT THESE COVER THAT THE IN-MEMORY TESTS CANNOT
 * ------------------------------------------------
 * {@see StreamConnection} is the only class that touches a socket, and
 * everything interesting about it is invisible to a scripted connection: a
 * write the kernel only partly accepts, a packet the network splits across
 * segments, a TLS record boundary that leaves bytes in PHP's own buffer, a
 * peer verification that silently accepts anything.
 *
 * They are a separate suite because they bind a port and spawn a process, and
 * they SKIP rather than fail when they cannot.
 *
 * WHAT THEY DO NOT COVER, AND THIS MATTERS
 * ----------------------------------------
 * These are NOT independent verification of the codec. The stub replays byte
 * sequences written in this repository, so a misreading of the specification
 * would be shared by the stub and the client, and every test here would pass.
 * {@see BrokerTest} is where the codec meets an implementation nobody here
 * wrote.
 */
final class SocketTest extends TestCase
{
    private const STUB = __DIR__ . '/support/mqtt-stub.php';

    private string $report = '';

    /** @var resource|null */
    private mixed $process = null;

    private string $certificate = '';

    protected function tearDown(): void
    {
        if (\is_resource($this->process)) {
            @proc_terminate($this->process);
            @proc_close($this->process);
        }

        $this->process = null;

        foreach ([$this->report, $this->certificate] as $path) {
            if ($path !== '' && is_file($path)) {
                @unlink($path);
            }
        }

        $this->report      = '';
        $this->certificate = '';
    }

    public function test_a_real_handshake_over_real_tcp(): void
    {
        $port   = $this->start();
        $client = $this->client($port);

        $connAck = $client->connect();

        self::assertTrue($connAck->isAccepted());
        self::assertTrue($client->isConnected());

        $client->disconnect();

        $report = $this->report();

        self::assertSame(1, $report['seen'][0]['type'], 'the stub received a CONNECT first');
        self::assertContains('protocol-level-5', $report['notes']);
    }

    /**
     * A publish larger than a single TCP segment. The write loop must send
     * every byte: a socket may accept 1,400 bytes of a 4 KB packet, and
     * treating that as success truncates it — which in a length-prefixed
     * protocol permanently desynchronises the peer rather than failing.
     */
    public function test_a_payload_far_larger_than_one_segment_arrives_whole(): void
    {
        $port   = $this->start();
        $client = $this->client($port);
        $client->connect();

        // 512 KiB, well past any socket send buffer.
        $payload = str_repeat('abcdefgh', 65536);

        $ack = $client->publish('big/payload', $payload, QoS::AtLeastOnce, timeout: 10.0);

        self::assertNotNull($ack);
        self::assertFalse($ack->isError());

        $client->disconnect();

        $report   = $this->report();
        $publishes = array_values(array_filter(
            $report['seen'],
            static fn (array $p): bool => $p['type'] === 3,
        ));

        self::assertCount(1, $publishes, 'exactly one PUBLISH arrived, not a truncated one plus junk');
        self::assertSame(
            bin2hex($payload),
            substr($publishes[0]['body'], -\strlen(bin2hex($payload))),
            'every byte of the payload arrived, in order',
        );
    }

    /**
     * The stub writes its replies in 1-byte pieces, so every reply crosses many
     * reads. This is the segmentation case the in-memory tests arrange by hand,
     * here produced by a real socket.
     */
    public function test_replies_split_into_single_bytes_are_reassembled(): void
    {
        $port   = $this->start(chunk: 1);
        $client = $this->client($port);

        $connAck = $client->connect();

        self::assertTrue($connAck->isAccepted(), 'a byte-at-a-time CONNACK was reassembled');

        $received = [];

        $client->subscribe('echo/topic', static function (MqttMessage $m) use (&$received): void {
            $received[] = $m->payload;
        }, timeout: 10.0);

        $client->publish('echo/topic', ['n' => 1], QoS::AtLeastOnce, timeout: 10.0);

        $deadline = microtime(true) + 5.0;

        while (microtime(true) < $deadline && $received === []) {
            $client->run(0.1);
        }

        self::assertSame(['{"n":1}'], $received, 'the echoed PUBLISH was reassembled too');

        $client->disconnect();
    }

    /**
     * Many small packets in flight at once — the shape a burst produces, and
     * the one where a `substr()` per packet would be quadratic.
     */
    public function test_a_burst_of_messages_is_all_delivered(): void
    {
        $port   = $this->start();
        $client = $this->client($port);
        $client->connect();

        $received = [];

        $client->subscribe('burst/+', static function (MqttMessage $m) use (&$received): void {
            $received[] = $m->payload;
        }, timeout: 10.0);

        for ($i = 0; $i < 200; $i++) {
            $client->publish('burst/' . $i, ['n' => $i]);
        }

        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline && \count($received) < 200) {
            $client->run(0.1);
        }

        self::assertCount(200, $received, 'every echoed message was framed and delivered');

        $client->disconnect();
    }

    public function test_a_real_pingreq_is_answered_over_a_socket(): void
    {
        $port   = $this->start();
        $client = $this->client($port, keepAlive: 2);
        $client->connect();

        // Longer than the 1.6s ping interval, so one goes out and must be
        // answered or the client declares the link half-open.
        $client->run(4.0);

        self::assertTrue($client->isConnected());

        $client->disconnect();

        $report = $this->report();
        $pings  = array_filter($report['seen'], static fn (array $p): bool => $p['type'] === 12);

        self::assertNotEmpty($pings, 'a PINGREQ really went down the socket');
    }

    /**
     * A broker that closes the socket must be reported as a lost connection and
     * NEVER as a timeout. A subscriber that treated a dead socket as a quiet one
     * would spin forever, report no error, and look exactly like a system where
     * nothing is being published.
     */
    public function test_a_closed_socket_is_reported_as_a_lost_connection(): void
    {
        $port   = $this->start();
        $client = $this->client($port);
        $client->connect();

        // Kill the broker out from under a live, healthy connection — which is
        // what a crash or a `kill -9` looks like from here, and the case a
        // client must not mistake for an idle topic.
        $process = $this->process;

        self::assertIsResource($process);

        @proc_terminate($process);
        @proc_close($process);
        $this->process = null;

        try {
            $client->run(3.0);

            self::fail('a peer that vanished must be reported, not read as silence');
        } catch (MqttException $e) {
            self::assertTrue($e->connectionLost, 'and reported as a LOST connection');
            self::assertStringContainsString('connection', $e->getMessage());
        }
    }

    public function test_dialling_a_port_nothing_is_listening_on_fails_quickly(): void
    {
        // Port 1 on loopback: privileged and unbound, so the connect is refused
        // rather than timing out.
        $client = $this->client(1, connectTimeout: 2.0);

        $started = microtime(true);

        try {
            $client->connect();
            self::fail('expected a refused connection');
        } catch (MqttException $e) {
            self::assertTrue($e->connectionLost);
            self::assertStringContainsString('Could not connect', $e->getMessage());
        }

        self::assertLessThan(
            2.0,
            microtime(true) - $started,
            'a refused connect must not wait out the whole timeout',
        );
    }

    /**
     * Failover: the first address is dead, the second answers. The rotation
     * lives in the transport because which endpoint we are on is a transport
     * fact — and because the CLIENT holds the subscription table, which has to
     * survive a reconnect or the process comes back connected and deaf.
     */
    public function test_failover_moves_to_the_second_address(): void
    {
        $port = $this->start();

        $options = ClientOptions::create(
            addresses: [
                ServerAddress::parse('mqtt://127.0.0.1:1'),
                ServerAddress::parse('mqtt://127.0.0.1:' . $port),
            ],
            clientId: ClientId::generate('sock'),
            connectTimeout: 2.0,
            readTimeout: 0.1,
        );

        $client = new MqttClient(
            new StreamConnection($options->addresses, $options->tls, $options->connectTimeout),
            $options,
        );

        $connAck = $client->connect();

        self::assertTrue($connAck->isAccepted(), 'the second address answered');

        $client->disconnect();
    }

    // ─── TLS ────────────────────────────────────────────────────────────────

    public function test_a_real_tls_handshake(): void
    {
        $certificate = $this->certificate();

        if ($certificate === null) {
            self::markTestSkipped('openssl could not generate a self-signed certificate here');
        }

        $port = $this->start(tls: $certificate);

        // Verification OFF, because the certificate is self-signed. That is
        // exactly the setting MQTT_TLS_INSECURE exposes, and the next test
        // shows what it costs.
        $client = $this->client($port, tls: TlsMode::Require, tlsVerify: false);

        $connAck = $client->connect();

        self::assertTrue($connAck->isAccepted());

        $client->disconnect();

        $report = $this->report();

        self::assertContains('tls', $report['notes'], 'the stub completed a TLS handshake');
    }

    /**
     * THE COST OF `MQTT_TLS_INSECURE`, demonstrated rather than described.
     *
     * With verification ON, a self-signed certificate is refused — which is the
     * correct outcome, because a client that accepts any certificate accepts an
     * interceptor as readily as the broker.
     */
    public function test_verification_rejects_a_self_signed_certificate(): void
    {
        $certificate = $this->certificate();

        if ($certificate === null) {
            self::markTestSkipped('openssl could not generate a self-signed certificate here');
        }

        $port   = $this->start(tls: $certificate);
        $client = $this->client($port, tls: TlsMode::Require, tlsVerify: true);

        try {
            $client->connect();
            self::fail('a self-signed certificate must not be accepted when verifying');
        } catch (MqttException $e) {
            self::assertTrue($e->connectionLost);
            // The useful text — "certificate verify failed", "self signed
            // certificate" — appears only in the warning PHP raises, which is
            // why the transport captures it.
            self::assertStringContainsString('MQTT_TLS_CA', $e->getMessage());
        }
    }

    /**
     * A burst over TLS. Records are decrypted whole, so a read smaller than a
     * record leaves bytes in PHP's own buffer — the classic select-versus-TLS
     * stall in most languages.
     *
     * This test does NOT prove that mechanism is handled: PHP's `stream_select`
     * was measured to account for its own buffer, so the stall does not arise
     * here and the `unread_bytes` fast path in the transport is an optimisation
     * rather than a fix. What this proves is the weaker and still worthwhile
     * claim that a burst over TLS arrives promptly and completely.
     */
    public function test_a_burst_over_tls_arrives_promptly(): void
    {
        $certificate = $this->certificate();

        if ($certificate === null) {
            self::markTestSkipped('openssl could not generate a self-signed certificate here');
        }

        $port   = $this->start(tls: $certificate);
        $client = $this->client($port, tls: TlsMode::Require, tlsVerify: false);
        $client->connect();

        $received = [];

        $client->subscribe('tls/+', static function (MqttMessage $m) use (&$received): void {
            $received[] = $m->payload;
        }, timeout: 10.0);

        for ($i = 0; $i < 50; $i++) {
            $client->publish('tls/' . $i, ['n' => $i, 'pad' => str_repeat('x', 500)]);
        }

        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline && \count($received) < 50) {
            $client->run(0.1);
        }

        self::assertCount(50, $received);

        $client->disconnect();
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    /** Start the stub on a free port and return it. */
    private function start(string $tls = '', int $chunk = 0): int
    {
        $port = $this->freePort();

        $this->report = sys_get_temp_dir() . '/mqtt-stub-' . bin2hex(random_bytes(6)) . '.json';

        $command = [\PHP_BINARY, self::STUB, (string) $port, $this->report];

        if ($tls !== '') {
            $command[] = '--tls';
            $command[] = $tls;
        }

        if ($chunk > 0) {
            $command[] = '--chunk';
            $command[] = (string) $chunk;
        }

        $descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
        $process     = proc_open($command, $descriptors, $pipes);

        if (!\is_resource($process)) {
            self::markTestSkipped('could not spawn the stub broker process');
        }

        $this->process = $process;

        // Wait for the stub's READINESS MARKER, not for the port.
        //
        // Probing the port would be a connection, and consuming one matters: an
        // earlier version did exactly that and then respawned the stub on the
        // same port, which races in TIME_WAIT and made every socket test fail
        // with "connection refused" on a port that had just worked.
        $ready    = $this->report . '.ready';
        $deadline = microtime(true) + 5.0;

        while (microtime(true) < $deadline) {
            if (is_file($ready)) {
                @unlink($ready);

                return $port;
            }

            usleep(20_000);
        }

        self::markTestSkipped('the stub broker did not start listening within 5s');
    }

    /** @return array{seen: list<array{type: int, flags: int, body: string}>, notes: list<string>} */
    private function report(): array
    {
        // Give the stub a moment to finish writing, then read ONCE. An earlier
        // version unlinked the file before reading it, so every test saw an
        // empty report and failed with a plausible, wrong explanation.
        $deadline = microtime(true) + 3.0;

        while (microtime(true) < $deadline) {
            if (is_file($this->report) && filesize($this->report) > 0) {
                break;
            }

            usleep(50_000);
        }

        $raw = is_file($this->report) ? (string) file_get_contents($this->report) : '';

        self::assertNotSame('', $raw, 'the stub wrote no report');

        $decoded = json_decode($raw, true);

        self::assertIsArray($decoded, 'the stub report was not JSON: ' . $raw);
        self::assertArrayNotHasKey('error', $decoded, 'the stub reported: ' . ($decoded['error'] ?? ''));

        /** @var array{seen: list<array{type: int, flags: int, body: string}>, notes: list<string>} $decoded */
        return $decoded;
    }

    private function client(
        int $port,
        int $keepAlive = 30,
        float $connectTimeout = 5.0,
        TlsMode $tls = TlsMode::Off,
        bool $tlsVerify = true,
        ProtocolVersion $version = ProtocolVersion::V5,
    ): MqttClient {
        $options = ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1:' . $port)],
            clientId: ClientId::generate('sock'),
            version: $version,
            keepAlive: $keepAlive,
            tls: $tls,
            tlsInsecure: !$tlsVerify,
            connectTimeout: $connectTimeout,
            readTimeout: 0.1,
        );

        return new MqttClient(
            new StreamConnection(
                addresses: $options->addresses,
                tlsMode: $options->tls,
                connectTimeout: $options->connectTimeout,
                tlsCa: $options->tlsCa,
                tlsVerify: $tlsVerify,
            ),
            $options,
        );
    }

    /** A port nothing is listening on, found by binding and releasing one. */
    private function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);

        if ($socket === false) {
            self::markTestSkipped('could not bind a loopback port');
        }

        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        if (!\is_string($name) || !str_contains($name, ':')) {
            self::markTestSkipped('could not read back the bound port');
        }

        return (int) substr($name, strrpos($name, ':') + 1);
    }

    /** A self-signed certificate, or null when openssl cannot make one here. */
    private function certificate(): ?string
    {
        if (!\function_exists('openssl_pkey_new')) {
            return null;
        }

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => \OPENSSL_KEYTYPE_RSA]);

        if ($key === false) {
            return null;
        }

        $csr = openssl_csr_new(
            ['commonName' => '127.0.0.1', 'countryName' => 'GB', 'organizationName' => 'hkm-test'],
            $key,
            ['digest_alg' => 'sha256'],
        );

        if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
            // openssl_csr_new is declared as returning `true` on some builds,
            // which is not a usable CSR — narrowed rather than cast.
            return null;
        }

        $cert = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);

        if ($cert === false) {
            return null;
        }

        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $keyPem);

        $this->certificate = sys_get_temp_dir() . '/mqtt-stub-' . bin2hex(random_bytes(6)) . '.pem';

        file_put_contents($this->certificate, $certPem . $keyPem);
        chmod($this->certificate, 0600);

        return $this->certificate;
    }
}
