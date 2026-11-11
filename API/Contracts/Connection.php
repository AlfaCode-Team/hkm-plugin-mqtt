<?php

declare(strict_types=1);

namespace Plugins\Mqtt\API\Contracts;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * The byte transport, abstracted so the protocol can be tested without a socket.
 *
 * WHY THIS SEAM EARNS ITS KEEP
 * ----------------------------
 * Everything interesting about a length-prefixed binary protocol is in the
 * cases that are hard to arrange against a real broker: a packet whose length
 * field arrives split across two TCP segments, a PUBLISH whose payload stops
 * one byte short, a connection that dies between the fixed header and the body,
 * a broker that answers a PINGREQ with nothing at all, a QoS 2 exchange
 * interrupted after PUBREC.
 *
 * Behind a real socket those are timing tricks and flaky tests. Behind this
 * interface they are three lines of scripted bytes.
 *
 * So {@see \Plugins\Mqtt\Application\Services\MqttClient} never touches a
 * stream, and the one class that does
 * ({@see \Plugins\Mqtt\Infrastructure\Transport\StreamConnection}) holds no
 * protocol knowledge at all — it moves bytes and reports failure. The tests
 * then come in two kinds that catch different things: in-memory ones covering
 * every protocol path, and socket ones proving the transport works over real
 * TCP, where segmentation is not something a test chose.
 *
 * THERE IS NO `enableTls()`, AND THAT IS THE POINT
 * -----------------------------------------------
 * The NATS equivalent of this interface needs one, because NATS negotiates TLS
 * in the clear: the server's greeting arrives first, unauthenticated, and the
 * upgrade happens afterwards — which is what makes TLS stripping possible
 * there.
 *
 * MQTT has no such negotiation. The client speaks first, and the socket was
 * either TLS from the first byte or it was not. So the decision belongs to
 * {@see self::open()}, is taken from local configuration before anything is
 * dialled, and there is no in-band moment for an attacker to interfere with.
 *
 * THE TIMEOUT / EOF DISTINCTION IS THE WHOLE CONTRACT OF `read()`
 * --------------------------------------------------------------
 * A read that returns nothing has two completely different meanings: "nothing
 * has happened yet", which is normal and constant on an idle broker, and "the
 * other end is gone", which must stop the loop. An implementation that returned
 * `''` for both would produce the worst failure this plugin can have — a
 * subscriber spinning on a dead socket, reporting no error, looking exactly
 * like a system where nothing is being published.
 *
 * Hence: `''` means the timeout elapsed, and end-of-stream THROWS.
 */
interface Connection
{
    /**
     * Establish the connection, with TLS already decided.
     *
     * Idempotent when already open.
     *
     * @throws MqttException with `connectionLost: true` on failure
     */
    public function open(): void;

    /**
     * Write every byte of $bytes, or throw.
     *
     * Partial writes are the implementation's problem, not the caller's. A
     * socket may accept 1,400 bytes of a 4 KB PUBLISH, and a client that
     * treated that as success would emit a truncated packet — which in a
     * length-prefixed protocol is not a recoverable error but a permanent
     * desynchronisation: the broker is still waiting for the rest of this
     * packet's declared body and will read the NEXT packet's header as part of
     * it.
     *
     * @throws MqttException
     */
    public function write(string $bytes): void;

    /**
     * Read up to $max bytes, waiting at most $timeout seconds.
     *
     * @param  float  $timeout seconds; `0.0` means do not wait at all
     * @return string the bytes read, or `''` when the timeout elapsed first
     * @throws MqttException with `connectionLost: true` at end-of-stream or on
     *                       a transport error — NEVER `''` for either
     */
    public function read(int $max, float $timeout): string;

    /** Was this connection established over TLS? */
    public function isEncrypted(): bool;

    /** Close, releasing the handle. Safe to call when already closed. */
    public function close(): void;

    public function isOpen(): bool;

    /** `host:port`, for logs and status output. NEVER a credential. */
    public function describe(): string;
}
