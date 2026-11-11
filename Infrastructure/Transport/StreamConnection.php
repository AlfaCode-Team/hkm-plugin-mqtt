<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Infrastructure\Transport;

use Plugins\Mqtt\API\Contracts\Connection;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\TlsMode;

/**
 * A TCP or TLS stream. Moves bytes; knows nothing about MQTT.
 *
 * Built on PHP streams rather than `ext-sockets` for one reason that matters:
 * OpenSwoole's coroutine runtime hooks `stream_socket_client`, `fread`,
 * `fwrite` and `stream_select`, so the same blocking code yields the coroutine
 * instead of the process. A `socket_recv()` loop does not get that, and inside
 * a realtime server it would block the whole worker — every WebSocket
 * connection it holds included.
 *
 * TLS IS ESTABLISHED BY DIALLING `ssl://`, NOT BY UPGRADING AFTERWARDS
 * -------------------------------------------------------------------
 * The NATS equivalent of this class connects in plaintext and then calls
 * `stream_socket_enable_crypto()`, because NATS negotiates the upgrade in band.
 * MQTT does not: the client speaks first, so the socket must already be
 * encrypted when the CONNECT goes out.
 *
 * Dialling `ssl://` makes that structural rather than sequential — there is no
 * window in which this client holds an unencrypted socket it intends to
 * upgrade, and therefore no code path in which a failure to upgrade leaves it
 * sending a CONNECT in the clear. That failure mode is worth designing out
 * rather than guarding: the credential is in the CONNECT.
 *
 * THE TLS BUFFER IS REAL; PHP ALREADY COPES WITH IT. MEASURED, NOT ASSUMED.
 * -----------------------------------------------------------------------
 * TLS is record-oriented, so one `fread` pulls a whole record off the socket,
 * decrypts it, and leaves whatever the caller did not take in PHP's own stream
 * buffer. In C — and in most languages' socket APIs — that is a notorious
 * stall: the kernel socket is now empty, `select` reports nothing to read, and
 * a complete decrypted message sits one layer up waiting for a packet that is
 * never coming.
 *
 * It was reasonable to expect PHP to have the same problem. It does not. A
 * direct probe on this platform read 100 bytes at a time out of an 8,000-byte
 * record and found:
 *
 *     fread(100) -> 100 bytes | unread_bytes=7900 | stream_select: READABLE
 *
 * — the buffer fills as expected, and `stream_select` reports the stream
 * readable anyway, because PHP's implementation short-circuits on its own
 * buffered bytes rather than only polling the file descriptor.
 *
 * So the `unread_bytes` check in {@see self::read()} is an OPTIMISATION, not a
 * correctness fix: it skips a `stream_select` syscall when the answer is
 * already known, which is the common case while draining a burst. It is kept
 * because it is one cheap metadata call and it keeps the code correct if the
 * read size ever drops below a TLS record — but it is not load-bearing, and
 * saying otherwise in a comment would leave the next reader afraid to touch it.
 *
 * FAILOVER LIVES HERE, NOT IN THE CLIENT
 * --------------------------------------
 * A broker cluster is a list of endpoints, and which one we are talking to is a
 * transport fact. Putting the rotation in the client instead would mean
 * rebuilding the client per attempt — and the client is where the SUBSCRIPTION
 * TABLE lives, which has to survive a reconnect or the process comes back
 * connected, healthy and deaf.
 *
 * So {@see self::open()} tries each address in turn and advances the starting
 * point each time, which spreads a fleet of reconnecting workers across the
 * surviving nodes instead of stampeding the first one in the list.
 */
final class StreamConnection implements Connection
{
    /** @var resource|null */
    private mixed $handle = null;

    private bool $encrypted = false;

    /** @var non-empty-list<ServerAddress> */
    private readonly array $addresses;

    /** Where the next {@see self::open()} starts in the list. */
    private int $cursor = 0;

    private ?ServerAddress $current = null;

    /**
     * @param non-empty-list<ServerAddress> $addresses tried in order, starting
     *        from a cursor that advances per connection
     * @param string $tlsCa a CA bundle for a broker with a private CA — the
     *        correct answer to a verification failure, as against turning
     *        verification off
     * @param bool $tlsVerify false accepts ANY certificate, so the TLS proves
     *        only that something is encrypting — not that it is the broker.
     *        Only ever for a self-signed development broker
     */
    public function __construct(
        array $addresses,
        private readonly TlsMode $tlsMode = TlsMode::Auto,
        private readonly float $connectTimeout = 5.0,
        private readonly string $tlsCa = '',
        private readonly bool $tlsVerify = true,
    ) {
        if ($addresses === []) {
            throw MqttException::connectFailed('(empty)', 'no MQTT broker address was configured');
        }

        $this->addresses = array_values($addresses);
    }

    /** The address this connection is on, or is about to try. */
    public function address(): ServerAddress
    {
        return $this->current ?? $this->addresses[$this->cursor % \count($this->addresses)];
    }

    public function open(): void
    {
        if ($this->isOpen()) {
            return;
        }

        $this->encrypted = false;
        $count           = \count($this->addresses);
        $failures        = [];
        $wantedTls       = false;

        for ($step = 0; $step < $count; ++$step) {
            $address = $this->addresses[($this->cursor + $step) % $count];
            $tls     = $this->tlsMode->shouldWrap($address->tls);
            $wantedTls = $wantedTls || $tls;

            [$handle, $failure] = $this->dial($address, $tls);

            if ($handle !== null) {
                $this->handle    = $handle;
                $this->current   = $address;
                $this->encrypted = $tls;
                // Advance PAST the one that worked, so a fleet reconnecting
                // after a node loss does not all land on the same survivor.
                $this->cursor = ($this->cursor + $step + 1) % $count;

                break;
            }

            $failures[] = $address->describe() . ': ' . $failure;
        }

        if ($this->handle === null) {
            $detail = $count === 1
                ? $failures[0]
                : 'every address failed — ' . implode('; ', $failures);

            if ($wantedTls) {
                throw MqttException::tlsRefused(
                    'Could not establish a TLS connection to the MQTT broker at ' . $this->describe()
                    . ': ' . $detail
                    . ($this->tlsVerify
                        ? '. If this broker uses a private CA, point MQTT_TLS_CA at its bundle — do '
                          . 'not disable verification, which accepts any certificate and so accepts an '
                          . 'interceptor as readily as the broker.'
                        : '. Verification is DISABLED on this client, so this is a handshake or '
                          . 'connectivity failure rather than a trust failure.'),
                );
            }

            throw MqttException::connectFailed($this->describe(), $detail);
        }

        $handle = $this->handle;

        // Blocking, with every wait done by stream_select first. A
        // non-blocking stream would turn every read into a busy loop, and
        // OpenSwoole's hook makes the blocking call yield the coroutine
        // anyway — so blocking here is both simpler and cheaper.
        stream_set_blocking($handle, true);

        // Not a timeout we rely on: PHP's stream read timeout is reported
        // through metadata rather than a return value, and distinguishing it
        // from end-of-stream afterwards is exactly the confusion read() must
        // not have. Set as a backstop so a pathological case cannot wedge
        // forever inside one fread.
        stream_set_timeout($handle, (int) max(1, ceil($this->connectTimeout)));
    }

    public function write(string $bytes): void
    {
        $handle = $this->handle;

        if ($handle === null) {
            throw MqttException::notConnected('write');
        }

        $total  = \strlen($bytes);
        $sent   = 0;
        $stalls = 0;

        // A socket accepts what fits in its send buffer. Treating a partial
        // write as success truncates the packet — and because MQTT is
        // length-prefixed, a truncated packet does not fail: it makes the
        // broker read the next packet's bytes as this one's body, and every
        // offset after it is wrong for the rest of the connection.
        while ($sent < $total) {
            $written = @fwrite($handle, substr($bytes, $sent));

            if ($written === false) {
                throw MqttException::connectionLost('the socket refused a write');
            }

            if ($written === 0) {
                // The send buffer is full. Wait for writability rather than
                // spinning; give up after a bounded number of empty passes so
                // a peer that has stopped reading cannot hold us here.
                if (++$stalls > 64) {
                    throw MqttException::connectionLost(
                        'the send buffer stayed full: the broker has stopped reading from this '
                        . 'connection, which is what a broker disconnecting a slow or over-quota '
                        . 'client looks like from here',
                    );
                }

                $write = [$handle];
                $read  = $except = [];
                @stream_select($read, $write, $except, 1, 0);

                continue;
            }

            $stalls = 0;
            $sent += $written;
        }
    }

    public function read(int $max, float $timeout): string
    {
        $handle = $this->handle;

        if ($handle === null) {
            throw MqttException::notConnected('read');
        }

        // A fast path, not a workaround. When PHP already holds decrypted
        // bytes there is nothing to wait for, so the syscall is skipped. See
        // the class docblock for why this is NOT the TLS-select stall it looks
        // like — PHP's stream_select accounts for this buffer itself.
        if (!$this->hasBufferedBytes($handle)) {
            $read  = [$handle];
            $write = $except = [];
            $micro = (int) round(($timeout - floor($timeout)) * 1_000_000);
            $ready = @stream_select($read, $write, $except, (int) floor(max(0.0, $timeout)), $micro);

            if ($ready === false) {
                // EINTR from a signal lands here. Reporting it as a lost
                // connection would make every SIGTERM look like a broker
                // outage, so it is reported as "nothing yet" and the caller's
                // loop re-checks its stop flag.
                return '';
            }

            if ($ready === 0) {
                return '';
            }
        }

        $bytes = @fread($handle, max(1, $max));

        if ($bytes === false) {
            throw MqttException::connectionLost('the socket refused a read');
        }

        if ($bytes === '') {
            // Readable, yet nothing came: the peer closed. This MUST be
            // distinguishable from a timeout — a subscriber that treats a dead
            // socket as a quiet one spins forever, reports no error, and looks
            // exactly like a system where nothing is being published.
            if (feof($handle)) {
                throw MqttException::connectionLost(
                    'the broker closed the connection'
                    . ($this->encrypted
                        ? ''
                        : '. On an unencrypted connection this is also what a TLS-only listener does '
                          . 'when spoken to in plaintext — check whether the broker expects TLS on '
                          . 'this port'),
                );
            }

            $meta = stream_get_meta_data($handle);

            if ($meta['timed_out'] === true) {
                return '';
            }

            throw MqttException::connectionLost('the socket reported readable but returned no bytes');
        }

        return $bytes;
    }

    public function isEncrypted(): bool
    {
        return $this->encrypted;
    }

    public function close(): void
    {
        if ($this->handle !== null) {
            @fclose($this->handle);
            $this->handle = null;
        }

        $this->encrypted = false;
        $this->current   = null;
    }

    public function isOpen(): bool
    {
        return $this->handle !== null;
    }

    /**
     * The endpoint, or the candidate list when not connected.
     *
     * Built from {@see ServerAddress::describe()}, which is host and port only.
     * Never the configured URL: an MQTT URL may carry a password, and this
     * string goes into every connection error and every status line.
     */
    public function describe(): string
    {
        if ($this->current !== null) {
            return $this->current->describe();
        }

        return implode(', ', array_map(
            static fn (ServerAddress $a): string => $a->describe(),
            $this->addresses,
        ));
    }

    /**
     * One dial attempt.
     *
     * @return array{0: resource|null, 1: string} the handle, or null and why not
     */
    private function dial(ServerAddress $address, bool $tls): array
    {
        $context = stream_context_create($tls ? ['ssl' => $this->tlsOptions($address)] : []);

        $errno   = 0;
        $errstr  = '';
        $warning = '';

        // The useful TLS text — "certificate verify failed", "unknown ca",
        // "wrong version number" — appears ONLY in the warning PHP raises;
        // $errstr is empty for a crypto failure. Without capturing it the
        // exception can say no more than "connection failed".
        set_error_handler(static function (int $_severity, string $message) use (&$warning): bool {
            $warning = $warning === '' ? $message : $warning . '; ' . $message;

            return true;
        });

        try {
            $handle = stream_socket_client(
                ($tls ? 'ssl://' : 'tcp://') . $address->endpoint(),
                $errno,
                $errstr,
                max(0.1, $this->connectTimeout),
                \STREAM_CLIENT_CONNECT,
                $context,
            );
        } finally {
            restore_error_handler();
        }

        if ($handle !== false) {
            return [$handle, ''];
        }

        // `stream_socket_client` declares $errstr by reference and leaves it
        // untouched on some failures, so it is narrowed to a string here rather
        // than trusted to be one.
        $errstr = \is_string($errstr) ? $errstr : '';
        $reason = $errstr !== '' ? $errstr : $warning;

        // The warning usually carries more than $errstr, so include both when
        // they differ — one says "operation failed" and the other says why.
        if ($errstr !== '' && $warning !== '' && !str_contains($errstr, $warning)) {
            $reason = $errstr . ' (' . $warning . ')';
        }

        return [null, $reason !== '' ? "{$reason} (errno {$errno})" : "errno {$errno}"];
    }

    /** @return array<string, mixed> */
    private function tlsOptions(ServerAddress $address): array
    {
        $options = [
            // The expected certificate name. Taken from the CONFIGURED host,
            // never from the socket's peer address: verifying a certificate
            // against the address we resolved to proves only that whoever
            // answered holds a certificate for themselves.
            'peer_name'           => $address->host,
            'verify_peer'         => $this->tlsVerify,
            'verify_peer_name'    => $this->tlsVerify,
            'allow_self_signed'   => !$this->tlsVerify,
            'SNI_enabled'         => true,
            'disable_compression' => true,
            'capture_peer_cert'   => false,
            'crypto_method'       => $this->cryptoMethod(),
        ];

        if ($this->tlsCa !== '') {
            // A file or a directory, and PHP needs to be told which. Getting
            // this wrong fails as "unable to get local issuer certificate",
            // which reads like a bad certificate rather than a misread path.
            $options[is_dir($this->tlsCa) ? 'capath' : 'cafile'] = $this->tlsCa;
        }

        return $options;
    }

    /**
     * Does PHP already hold bytes for this stream, decrypted or otherwise?
     *
     * `unread_bytes` is PHP's own read buffer, which on a TLS stream is where
     * the remainder of a partially-consumed record lives.
     *
     * @param resource $handle
     */
    private function hasBufferedBytes(mixed $handle): bool
    {
        $meta = stream_get_meta_data($handle);

        return $meta['unread_bytes'] > 0;
    }

    /**
     * TLS 1.2 and 1.3 only.
     *
     * `STREAM_CRYPTO_METHOD_TLS_CLIENT` would be the obvious constant and it
     * means "TLS 1.0 or anything newer" — so it silently permits TLS 1.0 and
     * 1.1, both deprecated by RFC 8996 and both with known attacks against
     * their CBC modes. Naming the two acceptable versions costs one line and
     * removes the downgrade.
     *
     * 1.3 is OR-ed in only when the constant exists, so this does not become a
     * fatal error on a build without it.
     */
    private function cryptoMethod(): int
    {
        $method = \STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;

        if (\defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
            $method |= \STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
        }

        return $method;
    }
}
