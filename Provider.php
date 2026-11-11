<?php

declare(strict_types=1);

namespace Plugins\Mqtt;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PubSubPort;
use Plugins\Mqtt\Application\Services\MqttClient;
use Plugins\Mqtt\Infrastructure\Adapters\MqttPubSub;
use Plugins\Mqtt\Infrastructure\Cli\MqttListenCommand;
use Plugins\Mqtt\Infrastructure\Cli\MqttPublishCommand;
use Plugins\Mqtt\Infrastructure\Cli\MqttStatusCommand;

/**
 * MQTT — a native 3.1.1 / 5.0 client, and the kernel's `PubSubPort` over it.
 *
 * Solves `pubsub.mqtt`. No MQTT library: the protocol is fifteen packet types
 * over a two-field fixed header, and the parts that are easy to get wrong are
 * the parts a library's defaults hide — whether the Remaining Length varint is
 * bounded before it is believed, whether a wildcard in a PUBLISH topic is
 * refused or silently delivered to nobody, whether the client identifier is
 * unique per PROCESS, whether a subscriber pings inside the keep-alive window,
 * and whether the TLS decision comes from configuration or from a port number.
 *
 * WHY MQTT WHEN THE NATS PLUGIN ALREADY SOLVES FAN-OUT
 * ---------------------------------------------------
 * Because the other end is often not ours. NATS is an excellent internal bus
 * and nothing speaks it but NATS clients. MQTT is what devices, gateways and
 * managed IoT brokers speak — so this plugin is for the case where the
 * application has to join a conversation it does not control.
 *
 * It also brings three things `pubsub.nats` structurally cannot:
 *
 * - **QoS 1 and 2**, so a publisher can know the broker took the message, and
 *   at QoS 2 that it took it exactly once.
 * - **Retained messages**, so a subscriber arriving late gets the current value
 *   of a topic rather than waiting for the next change.
 * - **Wills**, so the broker announces this process's disappearance on its
 *   behalf — which nothing a dead process could do would achieve.
 *
 * Both plugins implement the same `PubSubPort`, so a project binds ONE of them.
 * Binding both is not possible and would not mean anything: the port has one
 * implementation per deployment.
 *
 * ENABLING THIS PLUGIN DOES NOT BIND THE PORT
 * -------------------------------------------
 * An MQTT connection must live for the whole process, and `register()` binds
 * into the request-scoped container — so a client bound there would dial, TLS
 * and CONNECT once PER REQUEST and then throw the socket away. For MQTT that
 * is worse than wasteful: a per-request connection sharing one configured
 * client identifier would evict the long-lived subscriber on every request, for
 * the reasons set out in {@see \Plugins\Mqtt\Domain\ClientId}.
 *
 * So the port goes in the project's bootstrap, where the kernel keeps it
 * app-lifetime:
 *
 * ```php
 * // app/bootstrap/base.php
 * use Plugins\Mqtt\Infrastructure\Adapters\MqttFactory;
 *
 * ->withPorts([
 *     PubSubPort::class => MqttFactory::fromEnv(),
 * ])
 * ```
 *
 * Until that line exists, {@see \AlfacodeTeam\PhpServicePlatform\Kernel\Ports\NullPubSub}
 * is what a `Broadcaster` gets: publishing is a no-op and any realtime server
 * refuses to start. `mqtt:status` says so in as many words, because the symptom
 * of the missing line is "everything works and nothing arrives".
 *
 * NOTHING HERE TOUCHES AN HTTP REQUEST
 * ------------------------------------
 * No stage, no route, no hook, no event subscription. The plugin contributes a
 * port implementation and three commands, so a project that enables it and
 * binds nothing pays the cost of loading this file and nothing else.
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'pubsub.mqtt';
    }

    /**
     * Nothing.
     *
     * A transport has no business domain behind it. It does not read a
     * database, resolve an identity or render anything — it opens a socket and
     * moves bytes, and the one thing it needs (`LoggerPort`) is a port, which
     * resolves from the CoreContainer and is never listed here.
     *
     * @return list<string>
     */
    public function requires(): array
    {
        return [];
    }

    /**
     * NOTHING, and the empty list is the accurate answer.
     *
     * This plugin's contribution is a KERNEL PORT implementation plus three
     * commands. The port is bound by the project in `withPorts()`, not by this
     * module, so listing `PubSubPort` here would claim something false.
     *
     * {@see MqttClient} is not listed either, although `register()` does bind
     * it. `exposes` is a promise that a contract RESOLVES, and this one
     * resolves only once the project has bound the port — so declaring it
     * would make `ground probe` fail in every deployment that had not yet
     * written that bootstrap line, and it would be right to. A module wanting
     * the native surface (QoS 1 and 2, retained messages, wills, shared
     * subscriptions) declares `pubsub.mqtt` in its `requires[]` and resolves
     * {@see MqttClient} from the container, where the binding is waiting; what
     * it must not do is assume the binding can satisfy itself.
     *
     * @return list<class-string>
     */
    public function exposes(): array
    {
        return [];
    }

    public function register(ModuleContainer $container): void
    {
        // Resolved FROM the bound port rather than constructed, so a module
        // using QoS 1 shares the worker's one connection instead of opening a
        // second. For MQTT that is not merely tidier: a second connection would
        // need a different client identifier, because one sharing this
        // identifier would make the broker evict this connection — so
        // "construct your own client" is a trap rather than an option.
        //
        // A deployment that bound a different PubSubPort (Redis, NATS) gets a
        // message saying exactly that, rather than a TypeError three frames
        // down.
        $container->bind(MqttClient::class, static function ($c): MqttClient {
            $bound = $c->has(PubSubPort::class) ? $c->make(PubSubPort::class) : null;

            if ($bound instanceof MqttPubSub) {
                return $bound->client();
            }

            throw new \RuntimeException(
                MqttClient::class . ' is resolved from the bound PubSubPort, so that it shares the one '
                . 'connection this worker holds rather than opening a second — which for MQTT would '
                . 'also need its own client identifier, or the broker would disconnect this one. '
                . ($bound === null
                    ? 'No PubSubPort is bound: add `PubSubPort::class => MqttFactory::fromEnv()` to '
                      . 'withPorts() in the project bootstrap.'
                    : 'The bound PubSubPort is ' . $bound::class . ', not ' . MqttPubSub::class
                      . ' — so MQTT is not the configured bus in this deployment.'),
            );
        });
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        $cli->command(MqttStatusCommand::class);
        $cli->command(MqttListenCommand::class);
        $cli->command(MqttPublishCommand::class);
    }
}
