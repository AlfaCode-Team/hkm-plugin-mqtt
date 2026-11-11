<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * A DISCONNECT sent BY the broker — MQTT 5.0's one real diagnostic advance.
 *
 * WHAT 3.1.1 DOES INSTEAD, AND WHY IT IS SO MUCH WORSE
 * ---------------------------------------------------
 * In MQTT 3.1.1 a DISCONNECT is a client-to-server packet only. A broker that
 * wants rid of a client closes the socket, and that is all the client ever
 * learns. So every one of these becomes indistinguishable from a network
 * failure:
 *
 * - the client identifier was taken over by another process;
 * - the keep-alive window was missed;
 * - an administrator disconnected the client;
 * - the broker is shutting down;
 * - the broker is redirecting to another server;
 * - a cable was unplugged.
 *
 * A 3.1.1 client sees "connection reset by peer" for all six and retries, which
 * is right for the last one and wrong for the first — where retrying starts a
 * fight, each process evicting the other indefinitely.
 *
 * 5.0 adds the server-sent DISCONNECT with a reason code, and that is what lets
 * {@see \Plugins\Mqtt\Application\Services\MqttClient} stop retrying on
 * `0x8E Session taken over` instead of making the problem worse. It is the
 * strongest practical argument for defaulting `MQTT_VERSION` to 5.
 */
final readonly class ServerDisconnect
{
    public function __construct(
        public ReasonCode $reasonCode,
        public Properties $properties,
    ) {}

    /**
     * Would reconnecting make things worse rather than better?
     *
     * `0x8E` is the one that matters: another process holds this client id, so
     * reconnecting evicts it, and it will reconnect and evict us. The result is
     * two processes alternating forever, each looking like a flapping
     * connection and neither holding a usable subscription.
     *
     * `0x8A Banned` and `0x9D Server moved` are included because retrying
     * cannot succeed — the first by the broker's decision, the second because
     * the service is somewhere else and this client does not follow
     * redirections.
     */
    public function retryWouldWorsen(): bool
    {
        return match ($this->reasonCode) {
            ReasonCode::SessionTakenOver,
            ReasonCode::Banned,
            ReasonCode::ServerMoved => true,
            default                 => false,
        };
    }

    public function reasonString(): ?string
    {
        return $this->properties->string(Property::ReasonString);
    }

    /** Where to connect instead, on `0x9C`/`0x9D`. */
    public function serverReference(): ?string
    {
        return $this->properties->string(Property::ServerReference);
    }

    public function describe(): string
    {
        return $this->reasonCode->describe(PacketType::Disconnect);
    }
}
