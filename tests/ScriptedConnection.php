<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use Plugins\Mqtt\API\Contracts\Connection;
use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * A {@see Connection} whose inbound bytes are written by the test.
 *
 * This is what makes the protocol testable. Every interesting MQTT bug is a
 * boundary or ordering bug — a length split across two segments, an
 * acknowledgement that never comes, a DISCONNECT between two PUBLISHes — and
 * against a real broker those are timing tricks that produce flaky tests.
 * Here they are a list.
 *
 * `$script` IS A QUEUE OF READS, NOT A BUFFER
 * ------------------------------------------
 * Each entry is returned by one {@see self::read()} call, so the test controls
 * the SEGMENTATION as well as the content. That is the point:
 * `['\x20\x02', '\x00\x00']` delivers a CONNACK in two pieces and proves the
 * framing copes, which a single concatenated string would not.
 *
 * An entry of `''` is a read timeout — nothing arrived yet, which is the
 * ordinary state of an idle broker and must be distinguishable from a dead
 * socket.
 *
 * RUNNING OUT OF SCRIPT IS IDLE, NOT END-OF-STREAM
 * -----------------------------------------------
 * An exhausted script keeps returning `''`, because that is what a real quiet
 * broker does: a subscriber polling an idle topic reads nothing, repeatedly,
 * for as long as it likes. Treating exhaustion as EOF instead would make every
 * test have to predict exactly how many times the client's loop polls — which
 * depends on its read timeout and on the clock, so the number is an
 * implementation detail no test should encode.
 *
 * The forgotten-answer case is still caught, by the CLIENT's own deadline: a
 * test that does not script a PUBACK fails with "timed out waiting for PUBACK",
 * which names the missing packet. {@see self::MAX_IDLE_READS} is a backstop
 * against a genuine infinite loop, so a bug in the client surfaces as a failure
 * rather than a hung suite.
 *
 * {@see self::willClose()} scripts a real end-of-stream for the tests that need
 * one.
 */
final class ScriptedConnection implements Connection
{
    /**
     * Idle reads tolerated after the script runs out, before giving up.
     *
     * A backstop against a genuine infinite loop in the client, not a limit any
     * legitimate test should approach — a `run(0.2)` with a 0.05s read timeout
     * polls a handful of times.
     */
    private const MAX_IDLE_READS = 10_000;

    /** Everything the client has written, in order. */
    public string $written = '';

    public bool $opened = false;

    public int $opens = 0;

    public int $closes = 0;

    /** @var list<string> */
    private array $script;

    /**
     * Thrown by the next {@see self::read()} instead of returning bytes.
     *
     * For the lost-connection paths, which cannot be expressed as bytes.
     */
    private ?MqttException $failReadWith = null;

    private ?MqttException $failWriteWith = null;

    private ?MqttException $failOpenWith = null;

    /** Reads taken since the script ran out. */
    private int $idleReads = 0;

    /** Set by {@see self::willClose()} — a real end-of-stream. */
    private bool $closesAfterScript = false;

    /** @param list<string> $script one entry per read; '' is a timeout */
    public function __construct(array $script = [], private readonly bool $encrypted = false)
    {
        $this->script = $script;
    }

    /** Append bytes the client will read next. */
    public function willRead(string ...$chunks): self
    {
        foreach ($chunks as $chunk) {
            $this->script[] = $chunk;
        }

        return $this;
    }

    /** Make the next read fail as a lost connection. */
    public function failNextRead(string $reason = 'scripted failure'): self
    {
        $this->failReadWith = MqttException::connectionLost($reason);

        return $this;
    }

    /**
     * Script a real end-of-stream once the remaining script is consumed.
     *
     * For the tests that are specifically about a broker closing the socket,
     * as against one that is merely quiet.
     */
    public function willClose(): self
    {
        $this->closesAfterScript = true;

        return $this;
    }

    public function failNextWrite(string $reason = 'scripted failure'): self
    {
        $this->failWriteWith = MqttException::connectionLost($reason);

        return $this;
    }

    public function failNextOpen(string $reason = 'scripted failure'): self
    {
        $this->failOpenWith = MqttException::connectFailed('scripted', $reason);

        return $this;
    }

    /** Forget what the client has written so far. */
    public function clearWritten(): self
    {
        $this->written = '';

        return $this;
    }

    public function remainingScript(): int
    {
        return \count($this->script);
    }

    public function open(): void
    {
        ++$this->opens;

        if ($this->failOpenWith !== null) {
            $failure            = $this->failOpenWith;
            $this->failOpenWith = null;

            throw $failure;
        }

        $this->opened = true;
    }

    public function write(string $bytes): void
    {
        if ($this->failWriteWith !== null) {
            $failure             = $this->failWriteWith;
            $this->failWriteWith = null;

            throw $failure;
        }

        if (!$this->opened) {
            throw MqttException::notConnected('write');
        }

        $this->written .= $bytes;
    }

    public function read(int $max, float $timeout): string
    {
        if ($this->failReadWith !== null) {
            $failure            = $this->failReadWith;
            $this->failReadWith = null;

            throw $failure;
        }

        if (!$this->opened) {
            throw MqttException::notConnected('read');
        }

        if ($this->script === []) {
            if ($this->closesAfterScript) {
                // A real end-of-stream, which THROWS — never ''. A client that
                // could not tell a dead socket from a quiet one would spin
                // forever reporting no error, which is the worst failure this
                // plugin can have.
                throw MqttException::connectionLost('the scripted broker closed the connection');
            }

            if (++$this->idleReads > self::MAX_IDLE_READS) {
                throw MqttException::connectionLost(\sprintf(
                    'the client has polled an idle connection %d times without making progress, '
                    . 'which is a loop that is not advancing rather than a slow broker',
                    self::MAX_IDLE_READS,
                ));
            }

            // An idle broker. See the class docblock for why this is not EOF.
            return '';
        }

        $this->idleReads = 0;
        $chunk           = array_shift($this->script);

        // Honour $max, so a test can force the client to reassemble a packet
        // across several reads without having to split the script by hand.
        if (\strlen($chunk) > $max) {
            array_unshift($this->script, substr($chunk, $max));

            return substr($chunk, 0, $max);
        }

        return $chunk;
    }

    public function isEncrypted(): bool
    {
        return $this->encrypted;
    }

    public function close(): void
    {
        ++$this->closes;
        $this->opened = false;
    }

    public function isOpen(): bool
    {
        return $this->opened;
    }

    public function describe(): string
    {
        return 'scripted://test:1883';
    }
}
