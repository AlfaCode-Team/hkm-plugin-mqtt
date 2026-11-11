<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Mqtt\Domain\Exceptions\MqttException;
use Plugins\Mqtt\Domain\ProtocolVersion;
use Plugins\Mqtt\Domain\ServerAddress;
use Plugins\Mqtt\Infrastructure\Adapters\MqttFactory;

/**
 * `mqtt:status` — connect for real, and say what came back.
 *
 * WHY IT DIALS INSTEAD OF PRINTING THE CONFIGURATION
 * --------------------------------------------------
 * Every way a bus can be misconfigured produces one symptom: nothing arrives.
 * A command that only echoed `MQTT_URL` back would be green in every one of
 * them — wrong port, wrong password, TLS-only listener, a firewall, a topic the
 * credentials may not touch, a broker that refuses the protocol version. So
 * this does the whole handshake and reports what the broker actually said.
 *
 * IT ALSO REPORTS THE TWO THINGS THAT LOOK FINE AND ARE NOT
 * --------------------------------------------------------
 * A fixed `MQTT_CLIENT_ID`, which makes every process evict every other
 * process sharing it; and a configured `MQTT_SHARE_NAME`, which turns the
 * fan-out this port promises into a work queue. Both are legitimate settings
 * with narrow correct uses, and neither produces an error — so a status command
 * is the only place they will ever be mentioned.
 */
final class MqttStatusCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->name        = 'mqtt:status';
        $this->description = 'Connect to the MQTT broker and report what it says';

        $this->addOption(
            'topic',
            't',
            'Also publish one test message to this topic',
            acceptsValue: true,
        );
    }

    protected function handle(): int
    {
        $this->section('MQTT');

        // ── Configuration, before anything can fail ─────────────────────────
        try {
            $options = MqttFactory::optionsFromEnv();
        } catch (MqttException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->muted('Brokers    : ' . implode(', ', array_map(
            static fn (ServerAddress $a): string => $a->describe(),
            $options->addresses,
        )));
        $this->muted('Version    : MQTT ' . $options->version->label());
        $this->muted('TLS mode   : ' . $options->tls->value);
        $this->muted('Client id  : ' . ($options->clientId->isEmpty()
            ? '(empty — the broker will assign one)'
            : $options->clientId->value
              . ($options->clientId->generated ? ' (generated per process)' : ' (configured)')));
        $this->muted('Clean start: ' . ($options->cleanStart ? 'yes' : 'no (persistent session)'));
        $this->muted('Keep alive : ' . $options->keepAlive . 's');
        $this->muted('Default QoS: ' . $options->defaultQos->label());

        if ($options->topicSeparator !== '') {
            $this->muted(
                'Topic map  : channel "' . $options->topicSeparator . '" becomes MQTT "/" — so '
                . 'documents' . $options->topicSeparator . '42 publishes to '
                . $options->topicPrefix . 'documents/42',
            );
        } else {
            $this->muted('Topic map  : none, channel names are used as MQTT topics verbatim');
        }

        if ($options->topicPrefix !== '') {
            $this->muted('Prefix     : ' . $options->topicPrefix);
        }

        if (\count($options->addresses) > 1) {
            $this->muted('Failover   : tried in order, starting point rotates per connection');
        }

        // ── The settings that look fine and are not ─────────────────────────
        if ($options->clientId->risksEviction()) {
            $this->newLine();
            $this->warning(
                'MQTT_CLIENT_ID is set to a FIXED value. A client identifier is an exclusive name on '
                . 'the broker: [MQTT-3.1.4-3] requires the broker to DISCONNECT whoever held it when '
                . 'another connection presents it. If a web pool and a subscriber both read this '
                . 'configuration they will evict each other indefinitely, while every publish and '
                . 'every connect reports success. Correct only for ONE supervised process that needs '
                . 'the broker to hold its session across a restart; otherwise unset it and each '
                . 'process derives its own.',
            );
        }

        $portability = $options->clientId->portabilityWarning();

        if ($portability !== '' && !$options->clientId->isEmpty()) {
            $this->warning('Client identifier portability: ' . $portability);
        }

        if ($options->shareName !== '') {
            $this->newLine();
            $this->warning(
                'MQTT_SHARE_NAME is set to [' . $options->shareName . '], so subscriptions are made as '
                . '$share/' . $options->shareName . '/<filter>. That makes the broker deliver each '
                . 'message to ONE member of the group instead of to every subscriber — queue '
                . 'semantics, not the fan-out PubSubPort promises. Correct for a work queue; wrong for '
                . 'a realtime server, where it means one worker in the group sees the event and the '
                . 'clients held by the others never do.',
            );
        }

        if (!$options->cleanStart) {
            $this->warning(
                'Clean start is OFF, so the broker holds this client identifier\'s session — its '
                . 'subscriptions and its queued QoS 1 messages — after the connection ends'
                . ($options->sessionExpiry > 0
                    ? ', for ' . $options->sessionExpiry . 's.'
                    : ' indefinitely, because MQTT_SESSION_EXPIRY is 0. Every process that starts and '
                      . 'stops leaves one more session behind.'),
            );
        }

        if ($options->tlsInsecure) {
            $this->warning(
                'MQTT_TLS_INSECURE accepts ANY certificate, so the connection is encrypted against a '
                . 'passive observer and wide open to an active one — an interceptor presents its own '
                . 'certificate and is accepted. Use MQTT_TLS_CA with the private CA bundle instead.',
            );
        }

        // ── The handshake ───────────────────────────────────────────────────
        // Built from the options ALREADY PRINTED, not from a second
        // optionsFromEnv() — which generates a fresh client identifier, so the
        // two would disagree and this command would report a configuration it
        // was not using.
        $client  = MqttFactory::fromOptions($options)->client();
        $started = hrtime(true);

        try {
            $connAck = $client->connect();
        } catch (MqttException $e) {
            $this->newLine();
            $this->error($e->getMessage());
            $this->newLine();
            $this->muted(
                'A refused connection here is the WHOLE failure: nothing publishes and no subscriber '
                . 'runs. Check in this order — is the port 1883 (plaintext) or 8883 (TLS), and does '
                . 'the URL scheme match; does the broker need credentials this client was not given; '
                . 'does it speak the configured version (set MQTT_VERSION=3.1.1 for a broker that does '
                . 'not do 5.0, which includes nats-server).',
            );

            return self::FAILURE;
        }

        $handshake = (hrtime(true) - $started) / 1e6;

        $this->newLine();
        $this->success('Connected to ' . $client->describe());
        $this->muted(\sprintf('Handshake  : %.2f ms (TCP, TLS if any, CONNECT, CONNACK)', $handshake));

        // Only meaningful when an EMPTY id was sent, which is the only case in
        // which a broker assigns one. Comparing the two ids instead would
        // report any difference as an assignment — including the difference
        // between two separately generated ids, which is a bug in this command
        // rather than news about the broker.
        if ($options->clientId->isEmpty() && $client->clientId() !== '') {
            $this->muted('Assigned id: ' . $client->clientId() . ' (the broker chose this)');
        }

        if ($client->keepAlive() !== $options->keepAlive) {
            $this->muted(
                'Keep alive : ' . $client->keepAlive() . 's — IMPOSED by the broker, overriding the '
                . 'configured ' . $options->keepAlive . 's',
            );
        }

        $this->muted('Session    : ' . ($connAck->sessionPresent ? 'resumed an existing one' : 'new'));

        // ── What the broker will and will not do ────────────────────────────
        if ($options->version === ProtocolVersion::V5) {
            $this->newLine();
            $this->muted('Broker limits (from CONNACK):');
            $this->muted('  Maximum QoS            : ' . $connAck->maximumQoS()->value);
            $this->muted('  Receive maximum        : ' . $connAck->receiveMaximum()
                . ' unacknowledged QoS 1/2 publishes in flight');
            $this->muted('  Maximum packet size    : ' . ($connAck->maximumPacketSize() !== null
                ? $connAck->maximumPacketSize() . ' bytes'
                : 'not stated'));
            $this->muted('  Retained messages      : ' . ($connAck->retainAvailable() ? 'yes' : 'NO'));
            $this->muted('  Wildcard subscriptions : '
                . ($connAck->wildcardSubscriptionsAvailable() ? 'yes' : 'NO'));
            $this->muted('  Shared subscriptions   : '
                . ($connAck->sharedSubscriptionsAvailable() ? 'yes' : 'NO'));

            if ($options->defaultQos->value > $connAck->maximumQoS()->value) {
                $this->warning(
                    'MQTT_QOS is ' . $options->defaultQos->value . ' but this broker accepts at most '
                    . $connAck->maximumQoS()->value . '. Every publish would be refused with 0x9B QoS '
                    . 'not supported, which closes the connection.',
                );
            }

            if ($options->shareName !== '' && !$connAck->sharedSubscriptionsAvailable()) {
                $this->warning(
                    'MQTT_SHARE_NAME is set but this broker says shared subscriptions are not '
                    . 'available, so every subscription would be refused.',
                );
            }
        } else {
            $this->newLine();
            $this->muted(
                'MQTT 3.1.1 carries no broker limits in CONNACK, so the maximum QoS, the packet size '
                . 'ceiling and whether retained messages work are all unknowable from here — they are '
                . 'discovered by being disconnected. It also has no server-sent DISCONNECT, so an '
                . 'eviction is indistinguishable from a network failure.',
            );
        }

        if (!$client->isConnected()) {
            $this->error('The connection did not survive the handshake.');

            return self::FAILURE;
        }

        // ── An optional real publish, which is the only end-to-end proof ────
        $topic = $this->option('topic');

        if (\is_string($topic) && trim($topic) !== '') {
            $this->newLine();

            try {
                $started = hrtime(true);

                $ack = $client->publish(
                    trim($topic),
                    ['probe' => 'mqtt:status', 'at' => date(\DATE_ATOM)],
                    // QoS 1 deliberately, even though the port defaults to 0: a
                    // QoS 0 publish proves only that the socket accepted the
                    // bytes, which it would do just as happily into a
                    // connection the broker is closing. A PUBACK is the one
                    // thing that proves the broker took the message.
                    \Plugins\Mqtt\Domain\QoS::AtLeastOnce,
                );

                $elapsed = (hrtime(true) - $started) / 1e6;

                $this->success(\sprintf(
                    'Published to %s and the broker acknowledged it in %.2f ms',
                    trim($topic),
                    $elapsed,
                ));

                if ($ack !== null && $ack->reasonCode->isSilentNoOp()) {
                    $this->warning(
                        'The broker answered ' . $ack->reasonCode->describe($ack->type)
                        . ': it accepted the message and nobody was subscribed, so the message was '
                        . 'discarded. The publish worked; there was nothing to deliver it to.',
                    );
                }
            } catch (MqttException $e) {
                $this->error('The test publish failed: ' . $e->getMessage());
                $client->disconnect();

                return self::FAILURE;
            }
        }

        foreach ($client->warnings() as $warning) {
            $this->warning($warning);
        }

        // ── What this command cannot see ────────────────────────────────────
        $this->newLine();
        $this->muted('Not checked here:');
        $this->muted(
            '  - whether the project BOUND this adapter. `PubSubPort::class => MqttFactory::fromEnv()` '
            . 'in withPorts() is a separate step, and without it a Broadcaster gets NullPubSub: every '
            . 'publish is a no-op and nothing says so.',
        );
        $this->muted(
            '  - whether the credentials may publish to or subscribe on the topics the application '
            . 'uses. Broker access control is per topic, so a connection that works here can still '
            . 'be refused on every topic that matters. Pass --topic to test one.',
        );

        if (!$client->connAck()?->retainAvailable()) {
            $this->muted('  - retained messages, which this broker says it does not support.');
        }

        $client->disconnect();

        return self::SUCCESS;
    }
}
