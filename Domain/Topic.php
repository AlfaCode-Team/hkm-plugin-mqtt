<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

use Plugins\Mqtt\Domain\Exceptions\MqttException;

/**
 * Topic names, topic filters, and the matching rule — the correctness boundary.
 *
 * HOW THIS DIFFERS FROM THE NATS SUBJECT VALIDATOR, AND WHY IT STILL MATTERS
 * -------------------------------------------------------------------------
 * The NATS plugin's `Subject` class exists to stop a channel name becoming a
 * protocol command: NATS is a newline-terminated text protocol, so a subject
 * carrying a CRLF appends well-formed commands of the sender's choosing.
 *
 * **MQTT is immune to that, structurally.** Every string is length-prefixed, so
 * a topic is read as exactly as many bytes as the prefix said and never
 * re-parsed for delimiters. There is no byte a topic can contain that makes the
 * broker see a second packet. A reader arriving from the NATS plugin should
 * know that the headline threat there does not exist here.
 *
 * What replaces it is a quieter family of failures, all of which share one
 * shape — the publish succeeds and nobody receives it:
 *
 * 1. **A wildcard in a PUBLISH topic.** `[MQTT-4.7.1-1]` forbids it and
 *    `[MQTT-3.3.2-2]` repeats it, but the consequence is the point: a broker
 *    receiving `PUBLISH events/#` does not expand anything. Depending on the
 *    broker it either closes the connection or files the message under the
 *    literal topic `events/#`, which no subscriber can match, because a
 *    subscriber asking for `events/#` is asking for a wildcard. The message is
 *    accepted, acknowledged at QoS 1, and delivered to nobody — for ever, every
 *    time, with no error anywhere. This is the mirror of the NATS wildcard rule
 *    and the single most likely way to lose messages here.
 *
 * 2. **A `$`-prefixed topic.** `[MQTT-4.7.2-1]` forbids the broker from
 *    matching a filter that STARTS with a wildcard against a name beginning
 *    `$`. So `#` is not "everything": it is everything except the broker's own
 *    `$SYS` tree. A monitoring subscriber written against `#` silently sees no
 *    broker telemetry, and the fix is a second subscription to `$SYS/#`.
 *
 * 3. **An empty level.** `a//b` is three levels, the middle one zero-length,
 *    and it is VALID — adjacent separators are explicitly legal, a leading or
 *    trailing `/` creates a distinct topic, and `/` alone is a valid topic. So
 *    `finance` and `/finance` are different topics and nothing will tell you
 *    which one you meant. This class therefore permits empty levels (refusing
 *    them would break conforming deployments) and
 *    {@see self::hasEmptyLevel()} exists so a caller can warn.
 *
 * 4. **Case.** Topics are case sensitive: `Accounts` and `ACCOUNTS` are two
 *    topics. Nothing normalises, and `[MQTT-4.7.3-4]` forbids a broker from
 *    normalising either.
 *
 * NAME VERSUS FILTER ARE DIFFERENT METHODS, FOR THE SAME REASON AS NATS
 * --------------------------------------------------------------------
 * Publishing takes a NAME, where `+` and `#` are illegal. Subscribing takes a
 * FILTER, where they are meaningful in the positions the protocol allows and
 * nowhere else. A single permissive validator used for both is what produces
 * failure 1 above, so the split is enforced by having two entry points and no
 * shared lenient path.
 *
 * THE MATCHER IS HERE BECAUSE THIS CLIENT NEEDS IT
 * -----------------------------------------------
 * A broker sends a PUBLISH carrying the concrete topic, never the filter that
 * caused delivery. A client subscribed to `sensors/+/temp` and
 * `sensors/+/humidity` receives `sensors/3/temp` and has to work out for itself
 * which handler to call — so {@see self::matches()} is not a convenience, it is
 * required for routing, and it has to agree with the broker exactly or messages
 * go to the wrong handler.
 *
 * The two rules that are easy to get wrong, and are tested:
 *
 * - `sport/#` MATCHES the parent `sport` itself, because `#` includes the
 *   parent level. A naive level-count comparison gets this wrong.
 * - `sport/+` does NOT match `sport`, but it DOES match `sport/` — because `+`
 *   matches exactly one level, and the trailing separator creates an empty
 *   level for it to match.
 */
final class Topic
{
    public const SEPARATOR      = '/';
    public const MULTI_WILDCARD = '#';
    public const SINGLE_WILDCARD = '+';

    /** The prefix the broker reserves for itself. */
    public const RESERVED_PREFIX = '$';

    /** The MQTT 5.0 shared-subscription prefix. */
    public const SHARE_PREFIX = '$share';

    /**
     * This client's own ceiling on levels, not the protocol's.
     *
     * The protocol sets none: a 65,535-byte topic of nothing but `/` is 65,536
     * valid levels. The bound exists because {@see self::matches()} walks
     * levels, and an unbounded level count on an inbound topic lets whoever can
     * publish decide how much work this client does per message — the
     * denial-of-service shape, reached without any invalid input at all.
     *
     * 128 is far past any real hierarchy and still bounds the loop.
     */
    public const MAX_LEVELS = 128;

    private function __construct() {}

    // ─── Topic names (publish) ──────────────────────────────────────────────

    /** Is this usable as a PUBLISH topic name? Wildcards are refused. */
    public static function isValidName(string $topic): bool
    {
        return self::reasonNameInvalid($topic) === '';
    }

    /** @throws MqttException when the topic name must not go on the wire */
    public static function assertName(string $topic): void
    {
        $reason = self::reasonNameInvalid($topic);

        if ($reason !== '') {
            throw MqttException::invalidTopic($topic, $reason);
        }
    }

    /** Why this is unusable as a publish topic, or `''` when it is fine. */
    public static function reasonNameInvalid(string $topic): string
    {
        // [MQTT-4.7.3-1] "All Topic Names and Topic Filters MUST be at least
        // one character long." Note that this makes "/" valid and "" not.
        if ($topic === '') {
            return 'it is empty, and [MQTT-4.7.3-1] requires at least one character';
        }

        // The string-field rules apply to a topic like any other UTF-8 field,
        // and they catch the NUL that [MQTT-4.7.3-2] names separately.
        $string = Utf8::reasonInvalid($topic);

        if ($string !== '') {
            return $string;
        }

        if (str_contains($topic, self::MULTI_WILDCARD) || str_contains($topic, self::SINGLE_WILDCARD)) {
            return 'it contains a wildcard, and [MQTT-4.7.1-1] forbids "+" or "#" in a PUBLISH topic '
                . 'name — the broker does not expand them for a publisher, so this would be filed under '
                . 'the literal string and delivered to nobody, acknowledged and silent';
        }

        $levels = substr_count($topic, self::SEPARATOR) + 1;

        if ($levels > self::MAX_LEVELS) {
            return 'it has ' . $levels . ' levels, over this client\'s ' . self::MAX_LEVELS
                . '-level limit (see Topic::MAX_LEVELS for why that bound exists)';
        }

        return '';
    }

    // ─── Topic filters (subscribe) ──────────────────────────────────────────

    /** Is this usable as a SUBSCRIBE topic filter? Wildcards are permitted. */
    public static function isValidFilter(string $filter): bool
    {
        return self::reasonFilterInvalid($filter) === '';
    }

    /** @throws MqttException when the filter must not go on the wire */
    public static function assertFilter(string $filter): void
    {
        $reason = self::reasonFilterInvalid($filter);

        if ($reason !== '') {
            throw MqttException::invalidFilter($filter, $reason);
        }
    }

    /** Why this is unusable as a subscription filter, or `''` when it is fine. */
    public static function reasonFilterInvalid(string $filter): string
    {
        if ($filter === '') {
            return 'it is empty, and [MQTT-4.7.3-1] requires at least one character';
        }

        $string = Utf8::reasonInvalid($filter);

        if ($string !== '') {
            return $string;
        }

        // A shared subscription wraps an ordinary filter in `$share/<name>/`.
        // Validate the wrapper, then fall through to validate what it wraps —
        // so the wildcard rules are checked by exactly one piece of code.
        if (self::isShared($filter)) {
            return self::reasonSharedInvalid($filter);
        }

        $levels = explode(self::SEPARATOR, $filter);

        if (\count($levels) > self::MAX_LEVELS) {
            return 'it has ' . \count($levels) . ' levels, over this client\'s ' . self::MAX_LEVELS
                . '-level limit (see Topic::MAX_LEVELS for why that bound exists)';
        }

        $last = \count($levels) - 1;

        foreach ($levels as $index => $level) {
            if ($level === self::MULTI_WILDCARD) {
                // [MQTT-4.7.1-2] "#" must be on its own or follow a separator,
                // AND must be the last character. Being a whole level satisfies
                // the first half; this is the second.
                if ($index !== $last) {
                    return '"#" matches this level and every level below it, so [MQTT-4.7.1-2] allows it '
                        . 'only as the LAST level; here it is level ' . ($index + 1) . ' of '
                        . \count($levels);
                }

                continue;
            }

            if ($level === self::SINGLE_WILDCARD) {
                // [MQTT-4.7.1-3] "+" is legal at any level including first and
                // last. Nothing further to check.
                continue;
            }

            // A wildcard is a whole level or nothing. `sport+` and `sp#rt` are
            // not prefixes the broker understands — they are literals that will
            // never match, which is the silent-failure shape again.
            if (str_contains($level, self::MULTI_WILDCARD)) {
                return 'level ' . ($index + 1) . ' mixes "#" with other characters; [MQTT-4.7.1-2] '
                    . 'requires it to occupy an entire level, so this is a literal that matches nothing';
            }

            if (str_contains($level, self::SINGLE_WILDCARD)) {
                return 'level ' . ($index + 1) . ' mixes "+" with other characters; [MQTT-4.7.1-3] '
                    . 'requires it to occupy an entire level, so this is a literal that matches nothing';
            }
        }

        return '';
    }

    // ─── Shared subscriptions (MQTT 5.0) ────────────────────────────────────

    /**
     * Is this a shared subscription filter?
     *
     * Tested on the whole first level, not with `str_starts_with($f, '$share')`
     * — otherwise a perfectly ordinary topic like `$shareprices/eu` would be
     * mistaken for a malformed shared subscription and refused.
     */
    public static function isShared(string $filter): bool
    {
        return $filter === self::SHARE_PREFIX
            || str_starts_with($filter, self::SHARE_PREFIX . self::SEPARATOR);
    }

    /**
     * Build `$share/<group>/<filter>`.
     *
     * WHAT THIS BUYS, AND WHY A MULTI-WORKER DEPLOYMENT NEEDS IT
     * ---------------------------------------------------------
     * An ordinary MQTT subscription is fan-out: every subscriber gets every
     * message. That is right for a realtime server — four workers each holding
     * a quarter of the clients all need the event — and wrong for work, where
     * four workers subscribing to `jobs/+` means every job runs four times.
     *
     * A shared subscription makes the broker pick ONE member of the group per
     * message, which is queue semantics on a bus. It is the MQTT analogue of a
     * NATS queue group, and it is MQTT 5.0 only.
     *
     * @throws MqttException when the group name or the filter is unusable
     */
    public static function shared(string $group, string $filter): string
    {
        $reason = self::reasonShareNameInvalid($group);

        if ($reason !== '') {
            throw MqttException::invalidFilter(
                self::SHARE_PREFIX . self::SEPARATOR . $group . self::SEPARATOR . $filter,
                'its share name [' . MqttException::printable($group) . '] is unusable: ' . $reason,
            );
        }

        self::assertFilter($filter);

        return self::SHARE_PREFIX . self::SEPARATOR . $group . self::SEPARATOR . $filter;
    }

    /**
     * Split `$share/<group>/<filter>` into its two parts.
     *
     * @return array{0: string, 1: string} group, then the wrapped filter
     * @throws MqttException when this is not a well-formed shared filter
     */
    public static function splitShared(string $filter): array
    {
        $reason = self::reasonSharedInvalid($filter);

        if ($reason !== '') {
            throw MqttException::invalidFilter($filter, $reason);
        }

        // Exactly three pieces: the prefix, the group, and all the rest. The
        // limit matters — the wrapped filter may itself contain separators, and
        // an unlimited explode would cut `$share/g/a/b` into four and lose `b`.
        $parts = explode(self::SEPARATOR, $filter, 3);

        return [$parts[1], $parts[2]];
    }

    /** Why this is not a usable shared filter, or `''` when it is. */
    private static function reasonSharedInvalid(string $filter): string
    {
        $parts = explode(self::SEPARATOR, $filter, 3);

        if (\count($parts) < 3) {
            return 'a shared subscription is "$share/<group>/<filter>" and this has no '
                . (\count($parts) < 2 ? 'group or filter' : 'filter') . ' after the group';
        }

        $reason = self::reasonShareNameInvalid($parts[1]);

        if ($reason !== '') {
            return 'its share name [' . MqttException::printable($parts[1]) . '] is unusable: ' . $reason;
        }

        // The wrapped filter follows the ordinary rules, so defer to them. This
        // cannot recurse: `$share/g/$share/x` is caught because the wrapped
        // part is validated as a plain filter, where `$share` is just a level.
        $inner = self::reasonFilterInvalid($parts[2]);

        return $inner !== '' ? 'its wrapped filter [' . MqttException::printable($parts[2]) . '] ' . $inner : '';
    }

    /** Why a share name is unusable, or `''` when it is fine. */
    private static function reasonShareNameInvalid(string $group): string
    {
        if ($group === '') {
            return 'it is empty, and the share name must be at least one character';
        }

        if (str_contains($group, self::SEPARATOR)) {
            return 'it contains "/", which separates it from the filter it wraps';
        }

        if (str_contains($group, self::MULTI_WILDCARD) || str_contains($group, self::SINGLE_WILDCARD)) {
            return 'it contains a wildcard; the share name is a literal group label, not a filter';
        }

        return Utf8::reasonInvalid($group);
    }

    // ─── Matching ───────────────────────────────────────────────────────────

    /**
     * Does $filter match the concrete topic $name?
     *
     * This must agree with the broker exactly. It implements the three rules
     * that are easy to get wrong, each of which has a test:
     *
     * - `#` matches this level AND every level below, INCLUDING the parent, so
     *   `sport/#` matches the bare `sport`;
     * - `+` matches exactly one level, so `sport/+` matches `sport/` (an empty
     *   last level) but not `sport`;
     * - a filter whose FIRST level is a wildcard never matches a `$`-prefixed
     *   topic [MQTT-4.7.2-1], so `#` is not "everything".
     *
     * A shared filter matches on the filter it wraps: the `$share/<group>/`
     * part is addressing, not part of the pattern.
     */
    public static function matches(string $filter, string $name): bool
    {
        if ($filter === '' || $name === '') {
            return false;
        }

        if (self::isShared($filter)) {
            // Unwrap without throwing — matching is a predicate and a
            // malformed filter simply matches nothing. Validation belongs to
            // the subscribe path, which already refused it.
            $parts = explode(self::SEPARATOR, $filter, 3);

            if (\count($parts) < 3) {
                return false;
            }

            $filter = $parts[2];
        }

        $filterLevels = explode(self::SEPARATOR, $filter);
        $nameLevels   = explode(self::SEPARATOR, $name);

        // [MQTT-4.7.2-1]. The test is on the FIRST level only: `$SYS/#` is a
        // legitimate way to subscribe to broker telemetry, and only a filter
        // that *begins* with a wildcard is excluded from the `$` tree.
        if (
            str_starts_with($name, self::RESERVED_PREFIX)
            && ($filterLevels[0] === self::MULTI_WILDCARD || $filterLevels[0] === self::SINGLE_WILDCARD)
        ) {
            return false;
        }

        foreach ($filterLevels as $index => $level) {
            if ($level === self::MULTI_WILDCARD) {
                // Matches the rest, however many levels that is — including
                // zero, which is the parent-level rule: filter `sport/#` has
                // reached index 1 with nameLevels = ['sport'], so there is
                // nothing left and it still matches.
                return true;
            }

            if (!\array_key_exists($index, $nameLevels)) {
                // The filter is longer than the name and the extra is not `#`.
                // `sport/+` against `sport` lands here — correctly, a `+` has
                // nothing to match.
                return false;
            }

            if ($level === self::SINGLE_WILDCARD) {
                // Matches this one level whatever it is, INCLUDING an empty
                // one, which is what makes `sport/+` match `sport/`.
                continue;
            }

            if ($level !== $nameLevels[$index]) {
                // Byte comparison, deliberately: topics are case sensitive and
                // [MQTT-4.7.3-4] forbids normalising either side.
                return false;
            }
        }

        // Every filter level matched. It is a match only if the name is also
        // exhausted — `sport/tennis` must not match `sport/tennis/player1`.
        return \count($filterLevels) === \count($nameLevels);
    }

    // ─── Reporting helpers ──────────────────────────────────────────────────

    /**
     * Is this in the namespace the broker reserves for itself?
     *
     * Reported, not refused: `$SYS/#` is how you read broker telemetry, and
     * MQTT 5.0's own `$share` lives here too.
     */
    public static function isReserved(string $topic): bool
    {
        return str_starts_with($topic, self::RESERVED_PREFIX);
    }

    /**
     * Does this filter match every topic the broker will let it?
     *
     * True for `#` alone. Not for `a/#`, which is bounded by its prefix. Note
     * that even `#` excludes the `$` tree — see {@see self::matches()}.
     */
    public static function isCatchAll(string $filter): bool
    {
        return $filter === self::MULTI_WILDCARD;
    }

    /**
     * Does this topic contain a zero-length level?
     *
     * Valid, and almost always a mistake — `events//created` comes from an
     * interpolated variable that was empty, and it is a different topic from
     * `events/created` with nothing to say so.
     */
    public static function hasEmptyLevel(string $topic): bool
    {
        return $topic !== self::SEPARATOR
            && (str_contains($topic, self::SEPARATOR . self::SEPARATOR)
                || str_starts_with($topic, self::SEPARATOR)
                || str_ends_with($topic, self::SEPARATOR));
    }

    /**
     * The levels of a topic, for a caller that routes on them.
     *
     * @return list<string>
     */
    public static function levels(string $topic): array
    {
        return explode(self::SEPARATOR, $topic);
    }
}
