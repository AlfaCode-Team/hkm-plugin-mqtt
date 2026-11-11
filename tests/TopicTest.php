<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Mqtt;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\Topic;

/**
 * The topic rules, and the matcher, against the specification's own examples.
 *
 * The matcher is the part worth testing hardest, because it has to agree with
 * the BROKER exactly and nothing checks that at runtime. A disagreement does
 * not produce an error: it delivers a message to the wrong handler, or to none,
 * and the symptom is a feature that works for some topics.
 */
final class TopicTest extends TestCase
{
    // ─── Topic names (publish) ──────────────────────────────────────────────

    /**
     * A wildcard in a PUBLISH topic is the single most likely way to lose
     * messages here, and it is silent: the broker files the message under the
     * literal string, which no subscriber can match, and acknowledges it.
     */
    public function test_a_wildcard_is_refused_in_a_publish_topic(): void
    {
        foreach (['events/#', 'events/+', '#', '+', 'a/#/b', 'sport+'] as $topic) {
            self::assertFalse(Topic::isValidName($topic), $topic . ' must not be publishable');
            self::assertStringContainsString('wildcard', Topic::reasonNameInvalid($topic));
        }
    }

    public function test_assert_name_throws_and_writes_nothing(): void
    {
        $this->expectException(MqttException::class);
        $this->expectExceptionMessageMatches('/wildcard/');

        Topic::assertName('events/#');
    }

    /**
     * [MQTT-4.7.3-1] requires at least one character — which makes `/` valid
     * and `''` not. Easy to get backwards, and `/` really is a legal topic.
     */
    public function test_a_single_separator_is_a_valid_topic_but_empty_is_not(): void
    {
        self::assertTrue(Topic::isValidName('/'), '"/" is explicitly a valid topic');
        self::assertFalse(Topic::isValidName(''));
        self::assertStringContainsString('MQTT-4.7.3-1', Topic::reasonNameInvalid(''));
    }

    /**
     * Adjacent separators are legal and mean a zero-length level, so
     * `events//created` is a DIFFERENT topic from `events/created` and nothing
     * will tell you which you meant. Refusing them would break conforming
     * deployments, so they are permitted and reportable.
     */
    public function test_empty_levels_are_valid_and_reportable(): void
    {
        foreach (['a//b', '/finance', 'finance/', '/'] as $topic) {
            self::assertTrue(Topic::isValidName($topic), $topic . ' is valid per 4.7.1.1');
        }

        self::assertTrue(Topic::hasEmptyLevel('a//b'));
        self::assertTrue(Topic::hasEmptyLevel('/finance'));
        self::assertTrue(Topic::hasEmptyLevel('finance/'));
        self::assertFalse(Topic::hasEmptyLevel('a/b'));

        // "/" alone is excluded from the warning: it is a deliberate topic
        // rather than an interpolated variable that came out empty.
        self::assertFalse(Topic::hasEmptyLevel('/'));
    }

    /** [MQTT-4.7.3-2]: a NUL is forbidden anywhere in a topic. */
    public function test_a_null_byte_is_refused(): void
    {
        self::assertFalse(Topic::isValidName("events/\x00/created"));
        self::assertStringContainsString('U+0000', Topic::reasonNameInvalid("events/\x00"));
    }

    public function test_ill_formed_utf8_is_refused(): void
    {
        // A lone surrogate half, which [MQTT-1.5.4-1] forbids.
        self::assertFalse(Topic::isValidName("events/\xED\xA0\x80"));
        self::assertStringContainsString('UTF-8', Topic::reasonNameInvalid("events/\xED\xA0\x80"));
    }

    /** Multi-byte UTF-8 is legal and must not be refused. */
    public function test_valid_multibyte_utf8_is_accepted(): void
    {
        self::assertTrue(Topic::isValidName('capteurs/température'));
        self::assertTrue(Topic::isValidName('センサー/温度'));
        self::assertTrue(Topic::isValidName('sensors/🌡'));
    }

    // ─── Topic filters (subscribe) ──────────────────────────────────────────

    /** [MQTT-4.7.1-2]: `#` is valid only as the last level. */
    public function test_the_multi_level_wildcard_must_be_last(): void
    {
        self::assertTrue(Topic::isValidFilter('#'));
        self::assertTrue(Topic::isValidFilter('sport/#'));
        self::assertTrue(Topic::isValidFilter('sport/tennis/#'));

        self::assertFalse(Topic::isValidFilter('#/sport'));
        self::assertFalse(Topic::isValidFilter('sport/#/tennis'));
        self::assertStringContainsString('MQTT-4.7.1-2', Topic::reasonFilterInvalid('sport/#/tennis'));
    }

    /** [MQTT-4.7.1-3]: `+` is valid at any level, including first and last. */
    public function test_the_single_level_wildcard_is_valid_at_any_level(): void
    {
        foreach (['+', '+/tennis/#', 'sport/+', 'sport/+/player1', '+/+'] as $filter) {
            self::assertTrue(Topic::isValidFilter($filter), $filter . ' is valid per 4.7.1-3');
        }
    }

    /**
     * A wildcard is a whole level or nothing. `sport+` is not a prefix the
     * broker understands — it is a literal that matches nothing, which is the
     * silent-failure shape again.
     */
    public function test_a_wildcard_mixed_with_other_characters_is_refused(): void
    {
        foreach (['sport+', 'sport+/tennis', 'sp#rt', 'sport#'] as $filter) {
            self::assertFalse(Topic::isValidFilter($filter), $filter . ' must be refused');
            self::assertStringContainsString('entire level', Topic::reasonFilterInvalid($filter));
        }
    }

    // ─── Matching ───────────────────────────────────────────────────────────

    /**
     * The rule a naive level-count comparison gets wrong: `#` includes the
     * PARENT level, so `sport/#` matches the bare `sport`.
     */
    public function test_the_multi_level_wildcard_matches_the_parent_level(): void
    {
        self::assertTrue(Topic::matches('sport/#', 'sport'), '# includes the parent level');
        self::assertTrue(Topic::matches('sport/#', 'sport/tennis'));
        self::assertTrue(Topic::matches('sport/#', 'sport/tennis/player1'));

        self::assertTrue(Topic::matches('sport/tennis/player1/#', 'sport/tennis/player1'));
        self::assertTrue(Topic::matches('sport/tennis/player1/#', 'sport/tennis/player1/ranking'));
        self::assertTrue(Topic::matches('sport/tennis/player1/#', 'sport/tennis/player1/score/wimbledon'));

        self::assertFalse(Topic::matches('sport/#', 'sports'));
    }

    /**
     * The specification's own example, and the one most likely to be got
     * wrong: `sport/+` does NOT match `sport`, but it DOES match `sport/`,
     * because the trailing separator creates an empty level for `+` to match.
     */
    public function test_a_single_level_wildcard_matches_an_empty_level_but_not_a_missing_one(): void
    {
        self::assertFalse(Topic::matches('sport/+', 'sport'), '+ has nothing to match');
        self::assertTrue(Topic::matches('sport/+', 'sport/'), '+ matches the empty last level');

        self::assertTrue(Topic::matches('sport/tennis/+', 'sport/tennis/player1'));
        self::assertTrue(Topic::matches('sport/tennis/+', 'sport/tennis/player2'));
        self::assertFalse(Topic::matches('sport/tennis/+', 'sport/tennis/player1/ranking'));
    }

    /** The specification's `/finance` example. */
    public function test_a_leading_separator_creates_a_distinct_topic(): void
    {
        self::assertTrue(Topic::matches('+/+', '/finance'));
        self::assertTrue(Topic::matches('/+', '/finance'));
        self::assertFalse(Topic::matches('+', '/finance'));
    }

    /**
     * [MQTT-4.7.2-1]: a filter that STARTS with a wildcard never matches a
     * `$`-prefixed topic. So `#` is not "everything" — a monitoring subscriber
     * written against it silently sees no broker telemetry.
     */
    public function test_a_leading_wildcard_never_matches_the_dollar_tree(): void
    {
        self::assertFalse(Topic::matches('#', '$SYS/broker/clients'), '# excludes the $ tree');
        self::assertFalse(Topic::matches('+/broker/clients', '$SYS/broker/clients'));

        // But a filter that NAMES the $ level reaches it — which is how broker
        // telemetry is actually subscribed to.
        self::assertTrue(Topic::matches('$SYS/#', '$SYS/broker/clients'));
        self::assertTrue(Topic::matches('$SYS/broker/+', '$SYS/broker/clients'));
    }

    public function test_matching_is_case_sensitive(): void
    {
        self::assertFalse(Topic::matches('Accounts', 'ACCOUNTS'));
        self::assertFalse(Topic::matches('sport/Tennis', 'sport/tennis'));
        self::assertTrue(Topic::matches('sport/tennis', 'sport/tennis'));
    }

    public function test_a_filter_must_consume_the_whole_topic(): void
    {
        self::assertFalse(Topic::matches('sport/tennis', 'sport/tennis/player1'));
        self::assertFalse(Topic::matches('sport/tennis/player1', 'sport/tennis'));
    }

    #[DataProvider('matchVectors')]
    public function test_match_vectors(string $filter, string $topic, bool $expected): void
    {
        self::assertSame($expected, Topic::matches($filter, $topic), "{$filter} vs {$topic}");
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function matchVectors(): iterable
    {
        yield 'exact'                  => ['a/b/c', 'a/b/c', true];
        yield 'plus first level'       => ['+/b/c', 'a/b/c', true];
        yield 'plus middle level'      => ['a/+/c', 'a/b/c', true];
        yield 'plus last level'        => ['a/b/+', 'a/b/c', true];
        yield 'all plus'               => ['+/+/+', 'a/b/c', true];
        yield 'hash alone'             => ['#', 'a/b/c', true];
        yield 'hash after one level'   => ['a/#', 'a/b/c', true];
        yield 'hash equals parent'     => ['a/#', 'a', true];
        yield 'hash plus mixed'        => ['+/b/#', 'a/b/c/d', true];
        yield 'too few levels'         => ['a/+/c', 'a/c', false];
        yield 'too many levels'        => ['a/+', 'a/b/c', false];
        yield 'literal mismatch'       => ['a/b/c', 'a/x/c', false];
        yield 'empty level matched'    => ['a/+/c', 'a//c', true];
        yield 'empty topic'            => ['#', '', false];
        yield 'empty filter'           => ['', 'a', false];
        yield 'dollar with hash'       => ['#', '$x', false];
        yield 'dollar named'           => ['$x/#', '$x/y', true];
        yield 'dollar mid-topic is ok' => ['a/#', 'a/$b', true];
    }

    // ─── Shared subscriptions ───────────────────────────────────────────────

    public function test_a_shared_subscription_is_built_and_split(): void
    {
        $filter = Topic::shared('workers', 'jobs/+');

        self::assertSame('$share/workers/jobs/+', $filter);
        self::assertTrue(Topic::isShared($filter));
        self::assertSame(['workers', 'jobs/+'], Topic::splitShared($filter));
    }

    /**
     * The wrapped filter may contain separators, so the split must be limited
     * to three pieces — an unlimited explode would cut `$share/g/a/b` into four
     * and lose `b`.
     */
    public function test_splitting_keeps_a_multi_level_wrapped_filter_whole(): void
    {
        self::assertSame(['g', 'a/b/c'], Topic::splitShared('$share/g/a/b/c'));
    }

    public function test_a_shared_subscription_matches_on_the_filter_it_wraps(): void
    {
        self::assertTrue(Topic::matches('$share/workers/jobs/+', 'jobs/42'));
        self::assertFalse(Topic::matches('$share/workers/jobs/+', 'other/42'));
    }

    public function test_a_share_name_may_not_contain_a_separator_or_a_wildcard(): void
    {
        foreach (['a/b', 'a+b', 'a#b', ''] as $group) {
            try {
                Topic::shared($group, 'x');
                self::fail('the share name [' . $group . '] should have been refused');
            } catch (MqttException $e) {
                self::assertStringContainsString('share name', $e->getMessage());
            }
        }
    }

    public function test_a_malformed_shared_filter_is_refused(): void
    {
        // No filter after the group.
        self::assertFalse(Topic::isValidFilter('$share/group'));
        self::assertFalse(Topic::isValidFilter('$share'));
        self::assertStringContainsString('$share/<group>/<filter>', Topic::reasonFilterInvalid('$share/group'));
    }

    /**
     * `$shareprices/eu` is an ordinary topic, not a malformed shared
     * subscription — which a `str_starts_with($f, '$share')` test would get
     * wrong, refusing a perfectly good filter.
     */
    public function test_a_topic_merely_beginning_with_share_is_not_a_shared_subscription(): void
    {
        self::assertFalse(Topic::isShared('$shareprices/eu'));
        self::assertTrue(Topic::isValidFilter('$shareprices/eu'));
        self::assertTrue(Topic::isValidName('$shareprices/eu'));
    }

    /** The wrapped filter follows the ordinary rules, including the `#` position. */
    public function test_the_wrapped_filter_is_validated_too(): void
    {
        self::assertTrue(Topic::isValidFilter('$share/g/a/#'));
        self::assertFalse(Topic::isValidFilter('$share/g/a/#/b'));
        self::assertStringContainsString('wrapped filter', Topic::reasonFilterInvalid('$share/g/a/#/b'));
    }

    // ─── Bounds ─────────────────────────────────────────────────────────────

    /** [MQTT-4.7.3-3]: a topic must not exceed what a two-byte length can carry. */
    public function test_a_topic_over_65535_bytes_is_refused(): void
    {
        self::assertFalse(Topic::isValidName(str_repeat('a', 65536)));
        self::assertStringContainsString('65535', Topic::reasonNameInvalid(str_repeat('a', 65536)));
    }

    /**
     * The level cap is this client's own, not the protocol's: a 65,535-byte
     * topic of nothing but `/` is 65,536 valid levels, and the matcher walks
     * levels — so an unbounded count lets whoever can publish decide how much
     * work this client does per message.
     */
    public function test_an_absurd_level_count_is_refused(): void
    {
        $deep = str_repeat('a/', Topic::MAX_LEVELS + 1) . 'a';

        self::assertFalse(Topic::isValidName($deep));
        self::assertStringContainsString('level limit', Topic::reasonNameInvalid($deep));
    }

    public function test_reserved_and_catch_all_are_reported(): void
    {
        self::assertTrue(Topic::isReserved('$SYS/broker'));
        self::assertTrue(Topic::isReserved('$share/g/x'));
        self::assertFalse(Topic::isReserved('sport/tennis'));

        self::assertTrue(Topic::isCatchAll('#'));
        self::assertFalse(Topic::isCatchAll('a/#'), 'a/# is bounded by its prefix');
    }
}
