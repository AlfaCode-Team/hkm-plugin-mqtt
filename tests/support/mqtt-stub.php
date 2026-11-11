<?php

declare(strict_types=1);

/**
 * A minimal MQTT stub broker, run in a SECOND PROCESS over real TCP or TLS.
 *
 * WHAT THIS IS FOR, AND WHAT IT IS NOT FOR
 * ---------------------------------------
 * It exists to exercise
 * {@see \Plugins\Mqtt\Infrastructure\Transport\StreamConnection} — the one
 * class that touches a socket — against a real peer, over a real kernel, where
 * segmentation is chosen by the network rather than by a test. That catches
 * what an in-memory transport cannot: a partial write, a packet split across
 * TCP segments, a TLS record boundary, a peer verification that silently
 * accepts anything.
 *
 * It is NOT independent verification of the codec. It replays byte sequences
 * this repository wrote, so a misreading of the specification would be shared
 * by the stub and the client and every test would pass. `BrokerTest` is where
 * that is checked, against a broker nobody here wrote.
 *
 * HOW IT WORKS
 * ------------
 * It is deliberately almost not an MQTT implementation. It reads the fixed
 * header to find packet boundaries — the one piece of protocol it cannot avoid
 * — and then answers by TYPE from a fixed table:
 *
 *     CONNECT     -> CONNACK, accepted
 *     SUBSCRIBE   -> SUBACK granting QoS 0 for each filter in the packet
 *     UNSUBSCRIBE -> UNSUBACK
 *     PUBLISH     -> PUBACK/PUBREC when the QoS asks for one, and the message
 *                    echoed back on the same topic so a subscriber sees it
 *     PINGREQ     -> PINGRESP
 *     DISCONNECT  -> close
 *
 * Usage: `php mqtt-stub.php <port> <report-file> [--tls <cert.pem>] [--chunk N]`
 *
 * `--chunk N` writes replies N bytes at a time with a pause between, which is
 * how the "a packet arriving in pieces" cases are arranged on a real socket.
 */

$args   = $_SERVER['argv'] ?? [];
$count  = \count($args);
$port   = isset($args[1]) ? (int) $args[1] : 0;
$report = $args[2] ?? '';
$tlsCert = '';
$chunk   = 0;

for ($i = 3; $i < $count; $i++) {
    if ($args[$i] === '--tls' && isset($args[$i + 1])) {
        $tlsCert = $args[++$i];
    }

    if ($args[$i] === '--chunk' && isset($args[$i + 1])) {
        $chunk = (int) $args[++$i];
    }
}

if ($port <= 0 || $report === '') {
    fwrite(\STDERR, "usage: mqtt-stub.php <port> <report-file> [--tls cert.pem] [--chunk N]\n");
    exit(1);
}

$context = stream_context_create($tlsCert !== '' ? [
    'ssl' => [
        'local_cert'            => $tlsCert,
        'allow_self_signed'     => true,
        'verify_peer'           => false,
        'disable_compression'   => true,
    ],
] : []);

$listen = stream_socket_server(
    'tcp://127.0.0.1:' . $port,
    $errno,
    $errstr,
    \STREAM_SERVER_BIND | \STREAM_SERVER_LISTEN,
    $context,
);

if ($listen === false) {
    file_put_contents($report, json_encode(['error' => "bind failed: {$errstr} ({$errno})"]));
    exit(1);
}

/** @var list<array{type: int, flags: int, body: string}> */
$seen  = [];
$notes = [];

// A readiness marker, written as soon as the port is bound.
//
// The alternative — having the test probe the port — does not work for a stub
// that is deliberately this simple: the probe itself is a connection, and
// consuming it means either respawning (which races on the same port, in
// TIME_WAIT) or making the stub stateful enough to tell a probe from a client.
// A file is neither.
file_put_contents($report . '.ready', (string) $port);
// ─── Wire helpers ───────────────────────────────────────────────────────────

/** Decode a Variable Byte Integer at $offset, or null when incomplete. */
$varint = static function (string $buf, int $offset): ?array {
    $value      = 0;
    $multiplier = 1;

    for ($i = 0; $i < 4; $i++) {
        if (!isset($buf[$offset + $i])) {
            return null;
        }

        $byte   = \ord($buf[$offset + $i]);
        $value += ($byte & 0x7F) * $multiplier;

        if (($byte & 0x80) === 0) {
            return ['value' => $value, 'length' => $i + 1];
        }

        $multiplier *= 128;
    }

    return null;
};

$encodeVarint = static function (int $value): string {
    $out = '';

    do {
        $byte  = $value % 128;
        $value = intdiv($value, 128);

        if ($value > 0) {
            $byte |= 0x80;
        }

        $out .= \chr($byte & 0xFF);
    } while ($value > 0);

    return $out;
};

$wrap = static function (int $type, int $flags, string $body) use ($encodeVarint): string {
    return \chr(((($type << 4) | $flags)) & 0xFF) . $encodeVarint(\strlen($body)) . $body;
};

// ─── Serve connections, one at a time, until the deadline ───────────────────
//
// Sequential rather than one-shot: the tests need several connections (a
// reconnect, a failover, a second client) and a one-shot stub would have to be
// respawned on the same port, which races in TIME_WAIT.

$overall = microtime(true) + 30.0;

while (microtime(true) < $overall) {
    $client = @stream_socket_accept($listen, 1.0);

    if ($client === false) {
        continue;
    }

    if ($tlsCert !== '') {
        // Handled here rather than at accept, so a failure is reportable
        // instead of a silently dropped connection.
        if (@stream_socket_enable_crypto($client, true, \STREAM_CRYPTO_METHOD_TLS_SERVER) !== true) {
            $notes[] = 'tls-handshake-failed';
            @fclose($client);

            continue;
        }

        if (!\in_array('tls', $notes, true)) {
            $notes[] = 'tls';
        }
    }

    stream_set_blocking($client, true);
    stream_set_timeout($client, 5);

    /** Write $bytes, optionally in pieces, to force the client to reassemble. */
    $emit = static function (string $bytes) use ($client, $chunk): void {
        if ($chunk <= 0) {
            fwrite($client, $bytes);
            fflush($client);

            return;
        }

        foreach (str_split($bytes, $chunk) as $piece) {
            fwrite($client, $piece);
            fflush($client);
            usleep(1000);
        }
    };

    $buffer   = '';
    $running  = true;
    $deadline = microtime(true) + 20.0;

    // The protocol level this connection declared, read from its CONNECT.
    // The stub needs it because a 5.0 SUBACK and UNSUBACK carry a property
    // length byte that the 3.1.1 shapes do not — and omitting it makes a
    // correct client read the first reason code as the property length.
    $level = 4;

    while ($running && microtime(true) < $deadline && microtime(true) < $overall) {
        $read  = [$client];
        $write = $except = [];

        if (@stream_select($read, $write, $except, 0, 100000) > 0) {
            $bytes = @fread($client, 65536);

            if ($bytes === false || ($bytes === '' && feof($client))) {
                break;
            }

            $buffer .= $bytes;
        }

        // Frame whatever is complete.
        while (true) {
            if (\strlen($buffer) < 2) {
                break;
            }

            $header = \ord($buffer[0]);
            $length  = $varint($buffer, 1);

            if ($length === null) {
                break;
            }

            $total = 1 + $length['length'] + $length['value'];

            if (\strlen($buffer) < $total) {
                break;
            }

            $type   = $header >> 4;
            $flags  = $header & 0x0F;
            $body   = substr($buffer, 1 + $length['length'], $length['value']);
            $buffer = substr($buffer, $total);

            $seen[] = ['type' => $type, 'flags' => $flags, 'body' => bin2hex($body)];

            switch ($type) {
                case 1: // CONNECT -> CONNACK, accepted
                    $version = \ord($body[6]);
                    $level   = $version;
                    $note    = 'protocol-level-' . $version;

                    if (!\in_array($note, $notes, true)) {
                        $notes[] = $note;
                    }

                    // The 5.0 shape has a property block; the 3.1.1 shape does
                    // not, not even a zero byte.
                    $emit($wrap(2, 0, "\x00\x00" . ($version >= 5 ? "\x00" : '')));
                    break;

                case 3: // PUBLISH
                    $qos      = ($flags >> 1) & 0b11;
                    $topicLen = (\ord($body[0]) << 8) | \ord($body[1]);
                    $topic    = substr($body, 2, $topicLen);
                    $rest     = substr($body, 2 + $topicLen);
                    $packetId = 0;

                    if ($qos > 0) {
                        $packetId = (\ord($rest[0]) << 8) | \ord($rest[1]);
                        $rest     = substr($rest, 2);
                    }

                    if ($qos === 1) {
                        $emit($wrap(4, 0, \chr(($packetId >> 8) & 0xFF) . \chr($packetId & 0xFF)));
                    }

                    if ($qos === 2) {
                        $emit($wrap(5, 0, \chr(($packetId >> 8) & 0xFF) . \chr($packetId & 0xFF)));
                    }

                    // Echo it back at QoS 0, so a subscriber on this same
                    // connection receives a real PUBLISH to decode.
                    $payload = $rest;

                    if ($payload !== '' && \ord($payload[0]) === 0) {
                        // Drop an empty 5.0 property block.
                        $payload = substr($payload, 1);
                    }

                    $emit($wrap(
                        3,
                        0,
                        \chr(($topicLen >> 8) & 0xFF) . \chr($topicLen & 0xFF) . $topic . "\x00" . $payload,
                    ));
                    break;

                case 6: // PUBREL -> PUBCOMP
                    $emit($wrap(7, 0, substr($body, 0, 2)));
                    break;

                case 8: // SUBSCRIBE -> SUBACK, one granted QoS 0 per filter
                    $packetIdBytes = substr($body, 0, 2);
                    $offset        = 2;

                    // Skip a 5.0 property block. The stub does not know the
                    // version of THIS packet, so it uses the fact that a
                    // filter length of 0 is impossible: a zero byte here is a
                    // property block length.
                    if (isset($body[$offset]) && \ord($body[$offset]) === 0
                        && isset($body[$offset + 1]) && \ord($body[$offset + 1]) === 0) {
                        ++$offset;
                    }

                    $codes = '';

                    while ($offset + 2 <= \strlen($body)) {
                        $filterLen = (\ord($body[$offset]) << 8) | \ord($body[$offset + 1]);
                        $offset += 2 + $filterLen + 1; // filter + options byte
                        $codes .= "\x00";
                    }

                    // A 5.0 SUBACK is packetId + property length + codes; the
                    // 3.1.1 shape has no property length at all.
                    $emit($wrap(9, 0, $packetIdBytes . ($level >= 5 ? "\x00" : '') . $codes));
                    break;

                case 10: // UNSUBSCRIBE -> UNSUBACK
                    if ($level >= 5) {
                        // Count the filters so one reason code can be returned
                        // per filter, which 5.0 requires. 3.1.1's UNSUBACK has
                        // NO payload — §3.11, "The UNSUBACK Packet has no
                        // payload" — so it gets the bare packet identifier.
                        $offset = 2;

                        if (isset($body[$offset]) && \ord($body[$offset]) === 0
                            && isset($body[$offset + 1]) && \ord($body[$offset + 1]) === 0) {
                            ++$offset;
                        }

                        $codes = '';

                        while ($offset + 2 <= \strlen($body)) {
                            $filterLen = (\ord($body[$offset]) << 8) | \ord($body[$offset + 1]);
                            $offset += 2 + $filterLen;
                            $codes .= "\x00";
                        }

                        $emit($wrap(11, 0, substr($body, 0, 2) . "\x00" . $codes));
                    } else {
                        $emit($wrap(11, 0, substr($body, 0, 2)));
                    }
                    break;

                case 12: // PINGREQ -> PINGRESP
                    $emit($wrap(13, 0, ''));
                    break;

                case 14: // DISCONNECT
                    $running = false;
                    break;
            }
        }
    }

    @fclose($client);

    // Written after EVERY connection, so a test can read the report without
    // having to wait for the stub's whole lifetime to elapse. Written LAST and
    // never unlinked here: an earlier version removed the file before the test
    // read it, so every socket test saw an empty report and failed with a
    // plausible, wrong explanation.
    file_put_contents($report, json_encode([
        'seen'  => $seen,
        'notes' => $notes,
    ], \JSON_PRETTY_PRINT));
}

file_put_contents($report, json_encode([
    'seen'  => $seen,
    'notes' => $notes,
], \JSON_PRETTY_PRINT));

@fclose($listen);
