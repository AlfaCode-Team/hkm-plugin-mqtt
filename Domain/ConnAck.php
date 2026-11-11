<?php

declare(strict_types=1);

namespace Plugins\Mqtt\Domain;

/**
 * The broker's answer to CONNECT, and the only place it describes itself.
 *
 * WHY THIS IS MORE THAN A YES OR NO
 * ---------------------------------
 * CONNACK is where an MQTT 5.0 broker declares its limits, and they are limits
 * this client must respect rather than discover by being disconnected:
 *
 * - `Maximum QoS` — the highest QoS it will accept on a PUBLISH. Publishing
 *   above it earns `0x9B QoS not supported`.
 * - `Receive Maximum` — how many unacknowledged QoS 1/2 publishes may be in
 *   flight. Exceeding it earns `0x93` and a closed connection, so it is fed
 *   into {@see PacketIds::withLimit()}.
 * - `Maximum Packet Size` — the largest packet it will accept. Larger earns
 *   `0x95 Packet too large`.
 * - `Retain Available`, `Wildcard Subscription Available`, `Shared Subscription
 *   Available` — features that may simply not be there.
 * - `Server Keep Alive` — a keep-alive the broker IMPOSES. `[MQTT-3.1.2-21]`:
 *   when present "the Client MUST use that value instead" of its own, which
 *   means a client that ignores it is pinging on the wrong schedule and will be
 *   timed out while believing itself well within the window.
 *
 * Every one of these defaults to the permissive value when absent, which is
 * what makes a 3.1.1 CONNACK — which carries none of them — behave as it should.
 *
 * `sessionPresent` IS A CORRECTNESS SIGNAL, NOT A CURIOSITY
 * -------------------------------------------------------
 * It says whether the broker already held state for this client id.
 * `[MQTT-3.2.2-4]` requires a client with no session state that receives
 * `sessionPresent = 1` to CLOSE the connection — because the broker is about to
 * deliver messages for subscriptions this client does not know it has, and
 * acknowledge them against in-flight identifiers it never allocated.
 *
 * It is also the only reliable way to know whether subscriptions survived a
 * reconnect. A client that resumed a session does not need to re-subscribe; one
 * that did not, does — and getting that backwards means either duplicate
 * subscriptions or a subscriber silently receiving nothing.
 */
final readonly class ConnAck
{
    public function __construct(
        public bool $sessionPresent,
        public ReasonCode $reasonCode,
        public Properties $properties,
    ) {}

    public function isAccepted(): bool
    {
        return !$this->reasonCode->isError();
    }

    /**
     * The client identifier the broker assigned, when this client sent none.
     *
     * MQTT 5.0 only. In 3.1.1 an empty client id leaves this client unable to
     * know its own name — which is why {@see ClientId} generates one instead.
     */
    public function assignedClientId(): ?string
    {
        return $this->properties->string(Property::AssignedClientIdentifier);
    }

    /**
     * The keep-alive the broker insists on, if it overrode ours.
     *
     * `[MQTT-3.1.2-21]` makes using this mandatory when present.
     */
    public function serverKeepAlive(): ?int
    {
        return $this->properties->int(Property::ServerKeepAlive);
    }

    /** The highest QoS this broker accepts. Absent means 2. */
    public function maximumQoS(): QoS
    {
        return QoS::tryFrom($this->properties->int(Property::MaximumQoS, 2) ?? 2) ?? QoS::ExactlyOnce;
    }

    /**
     * How many unacknowledged QoS 1/2 publishes this broker allows in flight.
     *
     * Absent means 65,535 — the protocol's own default, and the whole
     * identifier space.
     */
    public function receiveMaximum(): int
    {
        $value = $this->properties->int(Property::ReceiveMaximum, PacketIds::MAX) ?? PacketIds::MAX;

        // A Receive Maximum of zero is a Protocol Error, so clamping rather
        // than trusting it: a zero here would make the allocator refuse every
        // QoS 1 publish for the life of the connection.
        return max(1, min($value, PacketIds::MAX));
    }

    /** The largest packet this broker accepts, or `null` for no stated limit. */
    public function maximumPacketSize(): ?int
    {
        return $this->properties->int(Property::MaximumPacketSize);
    }

    /** Does this broker store retained messages? Absent means yes. */
    public function retainAvailable(): bool
    {
        return $this->properties->bool(Property::RetainAvailable, true) ?? true;
    }

    /** Does this broker support `+` and `#` in filters? Absent means yes. */
    public function wildcardSubscriptionsAvailable(): bool
    {
        return $this->properties->bool(Property::WildcardSubscriptionAvailable, true) ?? true;
    }

    /** Does this broker support `$share/...`? Absent means yes. */
    public function sharedSubscriptionsAvailable(): bool
    {
        return $this->properties->bool(Property::SharedSubscriptionAvailable, true) ?? true;
    }

    /** A hint the broker offered about why it refused. */
    public function reasonString(): ?string
    {
        return $this->properties->string(Property::ReasonString);
    }

    /** Where the broker says to connect instead, on `0x9C`/`0x9D`. */
    public function serverReference(): ?string
    {
        return $this->properties->string(Property::ServerReference);
    }
}
