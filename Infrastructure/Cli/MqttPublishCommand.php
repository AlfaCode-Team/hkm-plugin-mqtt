<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\QoS;
use Plugins\Mqtt\Domain\Topic;
use Plugins\Mqtt\Infrastructure\Adapters\MqttFactory;

/**
 * `mqtt:publish <topic> [payload]` — put one message on the broker.
 *
 * The other half of `mqtt:listen`: between them they prove the broker works
 * without involving the application at all. Run the tap in one terminal and
 * this in another, and if the message arrives then everything from here to the
 * broker and back is fine — which narrows a realtime fault to the application.
 *
 * IT DEFAULTS TO QoS 1, UNLIKE THE PORT
 * -------------------------------------
 * {@see \Plugins\Mqtt\Infrastructure\Adapters\MqttPubSub} publishes at QoS 0,
 * because `PubSubPort` promises at-most-once and no more. This command defaults
 * to QoS 1 instead, and the difference is the whole point of a diagnostic: a
 * QoS 0 publish proves only that the local socket accepted the bytes, which it
 * will do just as happily into a connection the broker is in the middle of
 * closing. A PUBACK is the only thing that proves the broker took the message.
 *
 * So a success here means something, and `--qos 0` is available for when the
 * question is specifically about the fire-and-forget path.
 *
 * `--retain` IS NOT A FLAG TO SET CASUALLY
 * ---------------------------------------
 * A retained message is stored by the broker and delivered to every future
 * subscriber of that topic, indefinitely, until something replaces it. So a
 * test message published with `--retain` is not a test — it is a permanent
 * fixture that every later subscriber will receive as though it were current.
 * The command says so, and the way to remove one is an empty retained payload
 * to the same topic, which this supports.
 */
final class MqttPublishCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->name        = 'mqtt:publish';
        $this->description = 'Publish one message to an MQTT topic';

        $this->addArgument('topic', 'The topic name — no wildcards', required: true);
        $this->addArgument('payload', 'The payload; JSON is sent verbatim', required: false);

        $this->addOption('qos', 'q', 'QoS: 0, 1 (default) or 2', acceptsValue: true);
        $this->addOption('retain', 'r', 'Have the broker store this as the topic\'s retained message', acceptsValue: false);
        $this->addOption('clear-retained', '', 'Delete the topic\'s retained message (empty retained payload)', acceptsValue: false);
    }

    protected function handle(): int
    {
        $topic = trim((string) $this->argument('topic'));

        $this->section('MQTT publish');

        $reason = Topic::reasonNameInvalid($topic);

        if ($reason !== '') {
            $this->error('The topic [' . MqttException::printable($topic) . '] is unusable: ' . $reason);

            if (str_contains($topic, '#') || str_contains($topic, '+')) {
                $this->muted(
                    'Wildcards belong in a SUBSCRIPTION, not a publish. A broker does not expand them '
                    . 'for a publisher, so this would be filed under the literal string and delivered '
                    . 'to nobody. Use mqtt:listen to subscribe with a wildcard.',
                );
            }

            return self::FAILURE;
        }

        $clearRetained = (bool) $this->option('clear-retained');
        $retain        = $clearRetained || (bool) $this->option('retain');

        $raw = $this->argument('payload');
        $payload = $clearRetained ? '' : (\is_string($raw) ? $raw : '');

        if ($clearRetained && \is_string($raw) && $raw !== '') {
            $this->error(
                '--clear-retained deletes the retained message by publishing an EMPTY retained '
                . 'payload, so it cannot be combined with a payload. Drop one or the other.',
            );

            return self::FAILURE;
        }

        $qos = QoS::tryFrom((int) (is_numeric($this->option('qos')) ? $this->option('qos') : 1))
            ?? QoS::AtLeastOnce;

        $client = MqttFactory::clientFromEnv();

        try {
            $connAck = $client->connect();
        } catch (MqttException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->muted('Broker  : ' . $client->describe());
        $this->muted('Topic   : ' . $topic);
        $this->muted('QoS     : ' . $qos->label());
        $this->muted('Payload : ' . ($payload === ''
            ? '(empty)'
            : \strlen($payload) . ' bytes'));

        if ($retain && !$connAck->retainAvailable()) {
            $this->error(
                'This broker advertised that retained messages are not available, so a retained '
                . 'publish would be refused with 0x9A and the connection closed.',
            );
            $client->disconnect();

            return self::FAILURE;
        }

        if ($qos->value > $connAck->maximumQoS()->value) {
            $this->error(
                'This broker accepts at most QoS ' . $connAck->maximumQoS()->value
                . ', so QoS ' . $qos->value . ' would be refused with 0x9B and the connection closed. '
                . 'Use --qos ' . $connAck->maximumQoS()->value . '.',
            );
            $client->disconnect();

            return self::FAILURE;
        }

        try {
            $started = hrtime(true);

            $ack = $client->publish(
                $topic,
                // A string payload is sent VERBATIM — not re-encoded as JSON.
                // Re-encoding would quote a JSON argument into a JSON string,
                // so `{"a":1}` would arrive as "{\"a\":1}" and a subscriber
                // comparing payloads would see something it never sent.
                $payload,
                $qos,
                $retain,
            );

            $elapsed = (hrtime(true) - $started) / 1e6;
        } catch (MqttException $e) {
            $this->error($e->getMessage());
            $client->disconnect();

            return self::FAILURE;
        }

        $this->newLine();

        if ($ack === null) {
            $this->success(\sprintf('Written in %.2f ms.', $elapsed));
            $this->warning(
                'At QoS 0 there is no acknowledgement, so this means the bytes reached the socket and '
                . 'nothing more — a broker that refused the topic, or one in the middle of closing the '
                . 'connection, looks identical. Use --qos 1 to have the broker confirm it.',
            );
        } else {
            $this->success(\sprintf(
                'The broker acknowledged it in %.2f ms (%s).',
                $elapsed,
                $ack->reasonCode->describe($ack->type),
            ));

            if ($ack->reasonCode->isSilentNoOp()) {
                $this->warning(
                    'The broker accepted the message and NOBODY was subscribed, so it was discarded. '
                    . 'The publish worked; there was nothing to deliver it to. If a subscriber was '
                    . 'expected, compare its filter against this topic — matching is case sensitive '
                    . 'and a wildcard matches whole levels only.',
                );
            }

            $said = $ack->reasonString();

            if ($said !== null) {
                $this->muted('Broker said: ' . MqttException::printable($said));
            }
        }

        if ($clearRetained) {
            $this->muted(
                'The retained message for this topic is deleted. Future subscribers will receive '
                . 'nothing for it until something publishes again.',
            );
        } elseif ($retain) {
            $this->warning(
                'This message is RETAINED: the broker has stored it and will deliver it to every '
                . 'future subscriber of [' . $topic . '], indefinitely, until something replaces it. '
                . 'If that was a test message, remove it with: mqtt:publish ' . $topic
                . ' --clear-retained',
            );
        }

        foreach ($client->warnings() as $warning) {
            $this->warning($warning);
        }

        // A clean DISCONNECT rather than just closing the socket. The broker
        // discards the will on a clean exit, which is correct here — this
        // process exiting is not the event a will exists to announce.
        $client->disconnect();

        return self::SUCCESS;
    }
}
