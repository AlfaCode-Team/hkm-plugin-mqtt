<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\ClientId;
use Plugins\Mqtt\Domain\ClientOptions;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\ServerAddress;

/**
 * The Client Identifier — the most dangerous default in MQTT.
 *
 * `[MQTT-3.1.4-3]` makes the identifier an exclusive lock on a broker-wide
 * name, and connecting STEALS it: the previous holder is disconnected and the
 * new connection succeeds with no error anywhere. Two processes sharing one
 * identifier therefore evict each other indefinitely while every individual
 * operation reports success — which is why the default here is generated and a
 * configured one is warned about.
 */
final class ClientIdTest extends TestCase
{
    /**
     * Inside the set `[MQTT-3.1.3-5]` requires EVERY broker to accept: 1-23
     * bytes of `[0-9a-zA-Z]`. Anything longer or with other characters is
     * permitted but optional, so a generated identifier stays in the
     * guaranteed set — note this excludes `-`, which is why the prefix runs
     * straight into the random part.
     */
    public function test_a_generated_identifier_is_within_the_guaranteed_set(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $id = ClientId::generate();

            self::assertLessThanOrEqual(23, \strlen($id->value), $id->value);
            self::assertMatchesRegularExpression('/^[0-9a-zA-Z]+$/', $id->value);
            self::assertTrue($id->isGuaranteedAcceptable());
            self::assertSame('', $id->portabilityWarning());
            self::assertTrue($id->generated);
            self::assertFalse($id->risksEviction());
        }
    }

    public function test_a_generated_identifier_carries_the_prefix(): void
    {
        self::assertStringStartsWith('hkm', ClientId::generate()->value);
        self::assertStringStartsWith('web', ClientId::generate('web')->value);
    }

    /**
     * An unusable prefix must not be able to make the whole identifier
     * unusable, so it is sanitised and truncated rather than refused.
     */
    public function test_an_unusable_prefix_is_sanitised_not_propagated(): void
    {
        $id = ClientId::generate('my-app/worker #1');

        self::assertTrue($id->isGuaranteedAcceptable(), $id->value);
        self::assertStringStartsWith('mya', $id->value, 'punctuation stripped');
        self::assertLessThanOrEqual(23, \strlen($id->value));
    }

    public function test_a_long_prefix_is_truncated_to_leave_room_for_entropy(): void
    {
        $id = ClientId::generate(str_repeat('p', 100));

        self::assertSame(ClientId::MAX_GUARANTEED_LENGTH, \strlen($id->value));

        // The prefix is capped at exactly MAX_PREFIX_LENGTH, so the random
        // part keeps its full RANDOM_LENGTH — the entropy is never traded away
        // to fit a long prefix, because a collision is an eviction.
        self::assertStringStartsWith(str_repeat('p', ClientId::MAX_PREFIX_LENGTH), $id->value);
        self::assertSame(
            ClientId::MAX_PREFIX_LENGTH,
            \strlen($id->value) - ClientId::RANDOM_LENGTH,
        );

        // And the character right after the capped prefix is NOT another 'p'
        // from the prefix — it is the start of the random part.
        self::assertSame(
            ClientId::MAX_PREFIX_LENGTH + ClientId::RANDOM_LENGTH,
            ClientId::MAX_GUARANTEED_LENGTH,
        );
    }

    /**
     * Uniqueness is the entire point: a collision is an eviction, not an error.
     */
    public function test_generated_identifiers_do_not_collide(): void
    {
        $seen = [];

        for ($i = 0; $i < 5000; $i++) {
            $value = ClientId::generate()->value;

            self::assertArrayNotHasKey($value, $seen);
            $seen[$value] = true;
        }
    }

    // ─── Configured identifiers ─────────────────────────────────────────────

    public function test_a_configured_identifier_is_kept_verbatim(): void
    {
        $id = ClientId::configured('my-subscriber-01');

        self::assertSame('my-subscriber-01', $id->value);
        self::assertFalse($id->generated);
        self::assertTrue($id->risksEviction(), 'this is what the warning is for');
    }

    /**
     * NOT truncated or rewritten. A broker may well accept a 40-character
     * identifier, and silently shortening one would produce a different client
     * than the operator named — which for a persistent session means connecting
     * to the wrong session.
     */
    public function test_a_long_configured_identifier_is_kept_and_only_reported(): void
    {
        $long = str_repeat('a', 40);
        $id   = ClientId::configured($long);

        self::assertSame($long, $id->value, 'kept verbatim');
        self::assertFalse($id->isGuaranteedAcceptable());
        self::assertStringContainsString('MQTT-3.1.3-5', $id->portabilityWarning());
        self::assertStringContainsString('40 bytes', $id->portabilityWarning());
    }

    public function test_non_alphanumeric_characters_are_reported_as_a_portability_note(): void
    {
        $warning = ClientId::configured('web/worker-1')->portabilityWarning();

        self::assertStringContainsString('outside 0-9 a-z A-Z', $warning);
        self::assertStringContainsString('0x85', $warning, 'and names the reason code it would earn');
    }

    public function test_an_empty_configured_identifier_is_refused_with_a_pointer(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/assignedByBroker|MQTT_CLIENT_ID unset/');

        ClientId::configured('');
    }

    public function test_an_identifier_containing_a_null_byte_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/U\+0000/');

        ClientId::configured("web\x00worker");
    }

    // ─── The broker-assigned identifier ─────────────────────────────────────

    public function test_the_empty_identifier_asks_the_broker_to_assign_one(): void
    {
        $id = ClientId::assignedByBroker();

        self::assertTrue($id->isEmpty());
        self::assertFalse($id->isGuaranteedAcceptable());
        self::assertStringContainsString('the broker assigns one', $id->portabilityWarning());
        self::assertStringContainsString('clean session is off', $id->portabilityWarning());
    }

    // ─── The combinations ClientOptions refuses ─────────────────────────────

    /**
     * Resuming a session means naming the session to resume, and a zero-length
     * identifier names nothing. MQTT 3.1.1 requires the broker to refuse the
     * combination outright.
     */
    public function test_a_persistent_session_with_an_empty_identifier_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/names nothing/');

        ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            clientId: ClientId::assignedByBroker(),
            cleanStart: false,
        );
    }

    /**
     * THE ONE THAT ACTUALLY HAPPENS. A generated identifier is unique per
     * process, so a persistent session resumes nothing and leaves one
     * abandoned session on the broker per start — each holding its
     * subscriptions and queued messages, accumulating without limit on a
     * process that restarts regularly.
     */
    public function test_a_persistent_session_with_a_generated_identifier_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/never a session to resume/');

        ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            clientId: ClientId::generate(),
            cleanStart: false,
        );
    }

    /** The one correct use: one supervised process with a stable identifier. */
    public function test_a_persistent_session_with_a_configured_identifier_is_allowed(): void
    {
        $options = ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            clientId: ClientId::configured('the-one-subscriber'),
            cleanStart: false,
            sessionExpiry: 3600,
        );

        self::assertFalse($options->cleanStart);
        self::assertSame(3600, $options->sessionExpiry);
    }

    public function test_a_share_name_is_refused_on_311(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/MQTT 5.0 feature/');

        ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            version: ProtocolVersion::V311,
            shareName: 'workers',
        );
    }

    public function test_the_topic_separator_cannot_be_the_mqtt_separator(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/no-op dressed as a setting/');

        ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            topicSeparator: '/',
        );
    }

    public function test_a_wildcard_topic_prefix_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/unroutable/');

        ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            topicPrefix: 'events/#/',
        );
    }

    public function test_an_out_of_range_keep_alive_is_refused(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/0-65535/');

        ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            keepAlive: 70_000,
        );
    }

    /**
     * The ping interval is 80% of the keep-alive, not 100%: sending at exactly
     * the keep-alive leaves no room for the packet to travel, so a slow link
     * makes the broker's 1.5x deadline a coin flip.
     */
    public function test_the_ping_interval_leaves_a_margin(): void
    {
        $options = ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            keepAlive: 60,
        );

        self::assertSame(48.0, $options->pingInterval());
        self::assertLessThan(60, $options->pingInterval());
    }

    public function test_a_zero_keep_alive_disables_pinging(): void
    {
        $options = ClientOptions::create(
            addresses: [ServerAddress::parse('mqtt://127.0.0.1')],
            keepAlive: 0,
        );

        self::assertSame(0.0, $options->pingInterval());
    }
}
