<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Domain\TlsMode;

/**
 * Address parsing — the TLS inference, and keeping credentials out of logs.
 */
final class ServerAddressTest extends TestCase
{
    public function test_the_common_forms_parse(): void
    {
        $cases = [
            'mqtt://broker.example.com:1883' => ['broker.example.com', 1883, false],
            'mqtt://broker.example.com'      => ['broker.example.com', 1883, false],
            'broker.example.com:1883'        => ['broker.example.com', 1883, false],
            'broker'                         => ['broker', 1883, false],
            'mqtts://broker.example.com'     => ['broker.example.com', 8883, true],
            'mqtts://broker.example.com:1883' => ['broker.example.com', 1883, true],
            'tcp://127.0.0.1:1883'           => ['127.0.0.1', 1883, false],
            'ssl://127.0.0.1'                => ['127.0.0.1', 8883, true],
            'tls://127.0.0.1'                => ['127.0.0.1', 8883, true],
        ];

        foreach ($cases as $url => [$host, $port, $tls]) {
            $address = ServerAddress::parse($url);

            self::assertSame($host, $address->host, $url);
            self::assertSame($port, $address->port, $url);
            self::assertSame($tls, $address->tls, $url);
        }
    }

    /**
     * 8883 is the IANA-registered secure MQTT port, so a `mqtt://host:8883` is
     * almost certainly a TLS broker with the scheme typed from habit. Inferring
     * TLS beats dialling plaintext at a TLS listener and reporting a reset.
     */
    public function test_port_8883_implies_tls_even_under_a_plaintext_scheme(): void
    {
        self::assertTrue(ServerAddress::parse('mqtt://broker:8883')->tls);
        self::assertTrue(ServerAddress::parse('broker:8883')->tls);
    }

    /**
     * The reverse is NOT inferred: an explicit secure scheme is an
     * instruction, and downgrading it because of the port would be the mistake
     * this design avoids elsewhere.
     */
    public function test_an_explicit_secure_scheme_is_honoured_on_a_plaintext_port(): void
    {
        self::assertTrue(ServerAddress::parse('mqtts://broker:1883')->tls);
    }

    /**
     * A password in a URL has to work — it is how brokers document their
     * connection strings — and it must never reach a log line.
     */
    public function test_credentials_are_extracted_and_never_in_the_description(): void
    {
        $address = ServerAddress::parse('mqtt://alice:s3cr3t@broker.example.com:1883');

        self::assertSame('alice', $address->user);
        self::assertSame('s3cr3t', $address->pass);
        self::assertTrue($address->hasCredentials());

        self::assertSame('mqtt://broker.example.com:1883', $address->describe());
        self::assertStringNotContainsString('s3cr3t', $address->describe());
        self::assertStringNotContainsString('alice', $address->describe());
    }

    /** The rightmost `@`, because a password may legally contain one. */
    public function test_a_password_containing_an_at_sign_parses(): void
    {
        $address = ServerAddress::parse('mqtt://alice:p@ss@broker:1883');

        self::assertSame('alice', $address->user);
        self::assertSame('p@ss', $address->pass);
        self::assertSame('broker', $address->host);
    }

    public function test_percent_encoded_credentials_are_decoded(): void
    {
        $address = ServerAddress::parse('mqtt://user%40corp:p%3Ass@broker');

        self::assertSame('user@corp', $address->user);
        self::assertSame('p:ss', $address->pass);
    }

    /**
     * MQTT has no token concept, so a single credential field is a user name —
     * no ambiguity to resolve, unlike the NATS client.
     */
    public function test_a_single_credential_field_is_a_user_name(): void
    {
        $address = ServerAddress::parse('mqtt://alice@broker');

        self::assertSame('alice', $address->user);
        self::assertSame('', $address->pass);
    }

    /**
     * MQTT over WebSockets is a DIFFERENT framing — an HTTP upgrade, then MQTT
     * packets inside WebSocket frames. Accepting the scheme and dialling a raw
     * socket would produce a handshake that hangs rather than an error naming
     * the cause.
     */
    public function test_a_websocket_scheme_is_refused_with_an_explanation(): void
    {
        foreach (['ws://broker/mqtt', 'wss://broker/mqtt'] as $url) {
            try {
                ServerAddress::parse($url);
                self::fail($url . ' should be refused');
            } catch (MqttException $e) {
                self::assertStringContainsString('WebSockets', $e->getMessage());
                self::assertStringContainsString('TCP form only', $e->getMessage());
            }
        }
    }

    public function test_an_unknown_scheme_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/unknown scheme/');

        ServerAddress::parse('amqp://broker');
    }

    public function test_a_path_query_or_fragment_is_stripped_from_the_host(): void
    {
        foreach (['mqtt://broker:1883/', 'mqtt://broker:1883/mqtt', 'mqtt://broker:1883?x=1'] as $url) {
            self::assertSame('broker', ServerAddress::parse($url)->host, $url);
            self::assertSame(1883, ServerAddress::parse($url)->port, $url);
        }
    }

    public function test_bracketed_ipv6_parses_with_its_port(): void
    {
        $address = ServerAddress::parse('mqtt://[::1]:1883');

        self::assertSame('::1', $address->host);
        self::assertSame(1883, $address->port);
        self::assertSame('mqtt://[::1]:1883', $address->describe(), 'and goes back in brackets');
    }

    /**
     * A bare IPv6 address has no port: `::1:1883` is a valid address in its own
     * right, and guessing which colon is the separator is how a client ends up
     * dialling a host that does not exist.
     */
    public function test_a_bare_ipv6_address_is_not_split_on_its_own_colons(): void
    {
        $address = ServerAddress::parse('mqtt://::1');

        self::assertSame('::1', $address->host);
        self::assertSame(1883, $address->port, 'the default, not a port guessed from the address');
    }

    public function test_an_unclosed_ipv6_bracket_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/not closed/');

        ServerAddress::parse('mqtt://[::1:1883');
    }

    public function test_a_non_numeric_port_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/is not a number/');

        ServerAddress::parse('mqtt://broker:not-a-port');
    }

    public function test_an_out_of_range_port_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/outside 1-65535/');

        ServerAddress::parse('mqtt://broker:70000');
    }

    public function test_an_empty_address_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/no MQTT broker address/');

        ServerAddress::parse('   ');
    }

    /**
     * An entry is never skipped silently: a typo in one host of a three-host
     * cluster would then look like a working configuration that mysteriously
     * never reaches that node.
     */
    public function test_a_list_parses_in_order_and_refuses_a_bad_entry(): void
    {
        $list = ServerAddress::parseList('mqtt://a:1883, mqtt://b:1884 ,mqtt://c');

        self::assertCount(3, $list);
        self::assertSame(['a', 'b', 'c'], array_map(static fn ($x) => $x->host, $list));
        self::assertSame([1883, 1884, 1883], array_map(static fn ($x) => $x->port, $list));

        $this->expectException(MqttException::class);
        ServerAddress::parseList('mqtt://a:1883,mqtt://b:nope');
    }

    public function test_an_empty_list_is_refused(): void
    {
        $this->expectException(MqttException::class);

        ServerAddress::parseList(' , , ');
    }

    public function test_loopback_is_recognised_for_the_plaintext_warning(): void
    {
        self::assertTrue(ServerAddress::parse('mqtt://127.0.0.1')->isLoopback());
        self::assertTrue(ServerAddress::parse('mqtt://localhost')->isLoopback());
        self::assertTrue(ServerAddress::parse('mqtt://[::1]')->isLoopback());
        self::assertFalse(ServerAddress::parse('mqtt://broker.example.com')->isLoopback());
        self::assertFalse(ServerAddress::parse('mqtt://10.0.0.5')->isLoopback());
    }

    // ─── TlsMode ────────────────────────────────────────────────────────────

    /**
     * A typo must not silently disable encryption, and must not break every
     * loopback deployment either — so it lands on the documented default.
     */
    public function test_an_unrecognised_tls_mode_falls_back_to_auto(): void
    {
        self::assertSame(TlsMode::Auto, TlsMode::parse('reqiure'));
        self::assertSame(TlsMode::Auto, TlsMode::parse(''));
        self::assertSame(TlsMode::Auto, TlsMode::parse(null));
        self::assertSame(TlsMode::Auto, TlsMode::parse('nonsense'));

        self::assertSame(TlsMode::Off, TlsMode::parse('off'));
        self::assertSame(TlsMode::Require, TlsMode::parse('REQUIRE'));
        self::assertSame(TlsMode::Require, TlsMode::parse(' require '));
    }

    /**
     * `Auto` reads the ADDRESS, which is local configuration. Unlike the NATS
     * client, there is nothing on the wire for an attacker to rewrite — MQTT
     * has no in-band TLS negotiation at all.
     */
    public function test_the_mode_decides_whether_to_wrap(): void
    {
        self::assertFalse(TlsMode::Off->shouldWrap(true), 'off never wraps');
        self::assertTrue(TlsMode::Require->shouldWrap(false), 'require always wraps');
        self::assertTrue(TlsMode::Auto->shouldWrap(true), 'auto follows the address');
        self::assertFalse(TlsMode::Auto->shouldWrap(false));
    }
}
