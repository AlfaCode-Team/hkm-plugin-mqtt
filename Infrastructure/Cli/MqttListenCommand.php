<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\MqttMessage;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\Topic;
use Plugins\Mqtt\Infrastructure\Adapters\MqttFactory;

/**
 * `mqtt:listen <filter>` — a tap on the broker, for finding out what is there.
 *
 * WHAT THIS IS FOR
 * ----------------
 * Answering "is anything actually being published" without involving the
 * application. When a realtime feature does not work, the question splits in
 * two — is the publish side emitting, or is the delivery side not delivering —
 * and this answers the first half directly.
 *
 *     hkm cli mqtt:listen '#'            # everything (except the $ tree)
 *     hkm cli mqtt:listen 'documents/+'
 *     hkm cli mqtt:listen '$SYS/#'       # broker telemetry, if it publishes any
 *
 * `#` IS NOT EVERYTHING, AND THE EXCEPTION MATTERS HERE
 * ----------------------------------------------------
 * `[MQTT-4.7.2-1]` forbids the broker from matching a filter that STARTS with a
 * wildcard against a topic beginning `$`. So `#` misses the entire `$SYS` tree —
 * which is exactly where a broker publishes its own metrics, client lists and
 * connection counts. A tap that printed nothing from `#` and concluded "the
 * broker is idle" would be wrong in the one case where the broker had the most
 * to say, so this command says so when `#` is used.
 *
 * THE PAYLOAD IS PRINTED AS BYTES, NOT AS JSON
 * --------------------------------------------
 * MQTT says nothing about payload format, and on a broker shared with devices
 * most of it is not JSON: protobuf, CBOR, four raw bytes of float. Pretty-
 * printing it as JSON would show `null` for all of that and make a working
 * sensor look broken. So non-printable payloads are shown as a hex preview with
 * their length, and the length alone is often the answer.
 */
final class MqttListenCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->name        = 'mqtt:listen';
        $this->description = 'Subscribe to a topic filter and print what arrives';

        $this->addArgument('filter', 'The topic filter, e.g. "documents/+" or "#"', required: true);

        $this->addOption('qos', 'q', 'Requested QoS: 0, 1 or 2 (default 0)', acceptsValue: true);
        $this->addOption('seconds', '', 'Stop after this many seconds', acceptsValue: true);
        $this->addOption('count', 'c', 'Stop after this many messages', acceptsValue: true);
        $this->addOption('bytes', 'b', 'Print payloads as hex always, never as text', acceptsValue: false);
    }

    protected function handle(): int
    {
        $filter = trim((string) $this->argument('filter'));

        $this->section('MQTT tap');

        $reason = Topic::reasonFilterInvalid($filter);

        if ($reason !== '') {
            $this->error('The filter [' . MqttException::printable($filter) . '] is unusable: ' . $reason);

            return self::FAILURE;
        }

        $qos = QoS::tryFrom((int) (is_numeric($this->option('qos')) ? $this->option('qos') : 0))
            ?? QoS::AtMostOnce;

        $seconds = is_numeric($this->option('seconds')) ? (float) $this->option('seconds') : 0.0;
        $limit   = is_numeric($this->option('count')) ? (int) $this->option('count') : 0;
        $asBytes = (bool) $this->option('bytes');

        $client = MqttFactory::clientFromEnv();

        try {
            $connAck = $client->connect();
        } catch (MqttException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->muted('Broker  : ' . $client->describe());
        $this->muted('Filter  : ' . $filter);
        $this->muted('QoS     : ' . $qos->label());

        if (Topic::isCatchAll($filter)) {
            $this->warning(
                '"#" does NOT include topics beginning with "$": [MQTT-4.7.2-1] forbids the broker '
                . 'from matching a filter that starts with a wildcard against them. So the broker\'s '
                . 'own $SYS tree is invisible here — subscribe to "$SYS/#" separately for that.',
            );
        }

        if (!$connAck->wildcardSubscriptionsAvailable()
            && (str_contains($filter, '#') || str_contains($filter, '+'))
        ) {
            $this->error(
                'This broker advertised that wildcard subscriptions are not available, so this filter '
                . 'would be refused. Name a topic explicitly.',
            );
            $client->disconnect();

            return self::FAILURE;
        }

        $received = 0;

        try {
            $client->subscribe(
                $filter,
                function (MqttMessage $message) use (&$received, $limit, $asBytes, $client): void {
                    ++$received;

                    $this->info(\sprintf(
                        '[%s] %s%s%s  (%d bytes, QoS %d)',
                        date('H:i:s'),
                        $message->topic,
                        $message->retained ? ' [retained]' : '',
                        $message->dup ? ' [dup]' : '',
                        \strlen($message->payload),
                        $message->qos->value,
                    ));

                    $this->muted('  ' . $this->renderPayload($message, $asBytes));

                    foreach ($message->properties()->toArray() as $name => $value) {
                        $this->muted('  · ' . $name . ': ' . MqttException::printable((string) $value, 120));
                    }

                    if ($limit > 0 && $received >= $limit) {
                        // Stops the loop at its next pass. Not an exception:
                        // throwing out of a handler unwinds the read loop and
                        // would be reported as a failure rather than as the
                        // requested finish.
                        $client->stop();
                    }
                },
                $qos,
            );
        } catch (MqttException $e) {
            $this->error($e->getMessage());
            $client->disconnect();

            return self::FAILURE;
        }

        $this->success('Subscribed. Ctrl-C to stop.');

        if ($qos !== QoS::AtMostOnce) {
            $this->muted(
                'At QoS ' . $qos->value . ' the broker expects acknowledgements, which this tap sends '
                . 'automatically — so messages it receives are CONSUMED from this client\'s session '
                . 'rather than merely observed.',
            );
        }

        $this->newLine();

        try {
            $client->run($seconds);
        } catch (MqttException $e) {
            $this->newLine();
            $this->error($e->getMessage());

            $disconnect = $client->lastDisconnect();

            if ($disconnect !== null && $disconnect->retryWouldWorsen()) {
                $this->muted(
                    'This is not a transient fault and reconnecting would make it worse. '
                    . $disconnect->reasonCode->remedy(),
                );
            }

            return self::FAILURE;
        } finally {
            $client->disconnect();
        }

        $this->newLine();
        $this->success($received . ' message(s) received.');

        if ($received === 0) {
            $this->muted(
                'Nothing arrived. That is a real answer: the publish side is not emitting on this '
                . 'filter. Check that the publisher\'s topic matches — remember the channel-to-topic '
                . 'translation (mqtt:status prints it), that matching is case sensitive, and that a '
                . 'wildcard matches whole levels only, so "documents/+" does not match "documents".',
            );
        }

        return self::SUCCESS;
    }

    /**
     * A payload rendered for a terminal.
     *
     * Text when it is printable text, hex otherwise. The distinction is made on
     * the BYTES rather than on a Content Type property, because almost nothing
     * sets that property and a wrong guess here hides the one piece of
     * information this command exists to show.
     */
    private function renderPayload(MqttMessage $message, bool $asBytes): string
    {
        if ($message->payload === '') {
            return '(empty payload'
                . ($message->retained
                    ? ' — on a retained message this DELETES the retained value for the topic)'
                    : ')');
        }

        $preview = substr($message->payload, 0, 400);

        if (!$asBytes && mb_check_encoding($preview, 'UTF-8') && !preg_match('/[\x00-\x08\x0E-\x1F]/', $preview)) {
            return $preview . (\strlen($message->payload) > 400 ? '… (truncated)' : '');
        }

        return 'hex: ' . implode(' ', str_split(bin2hex(substr($preview, 0, 64)), 2))
            . (\strlen($message->payload) > 64 ? '…' : '');
    }
}
