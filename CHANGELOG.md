# Changelog

All notable changes to `hkm-plugin-mqtt` are documented here.

## [1.0.0] - 2026-11-12

First release. Solves `pubsub.mqtt`.

- Requires kernel `^1.21.0`: this plugin implements the kernel's `PubSubPort`
  and `NullPubSub`, which ship in 1.21.0 and exist in no earlier release.

### Added

- **A native MQTT 3.1.1 and 5.0 client.** No MQTT library: the packet codec, the
  topic validator and matcher, the framing and the client state machine are all
  here and testable without a broker.
- **`PubSubPort` over it** (`MqttFactory::fromEnv()`), publishing and subscribing
  at QoS 0 — which is what that port promises and no more.
- **The native surface** for what a fan-out port cannot express: QoS 1 and 2,
  retained messages, wills, shared subscriptions and the MQTT 5.0 properties.
  Resolved from the bound port so it shares the worker's one connection.
- **Three commands**: `mqtt:status` (dials for real and reports the broker's own
  limits), `mqtt:listen` (a tap), `mqtt:publish`.
- **TLS** over `mqtts://` or port 8883, with a private-CA bundle via
  `MQTT_TLS_CA`. TLS 1.2 and 1.3 only.
- **Failover** across a comma-separated `MQTT_URL`, with a starting point that
  rotates per connection so a reconnecting fleet does not stampede one survivor.

### Deliberate decisions worth knowing

- **The client identifier is generated per process by default.**
  `[MQTT-3.1.4-3]` makes it an exclusive broker-wide name, and connecting with
  one somebody else holds evicts them with no error on either side. A fixed
  `MQTT_CLIENT_ID` is supported and warned about; see the README.
- **No `daemon` block.** The kernel's provisioning mechanism pins a SHA-256 per
  platform and refuses an unpinned one, and no MQTT broker publishes one
  verifiable archive per platform (mosquitto cuts no releases; NanoMQ is linux
  `.deb`/`.rpm`; EMQX has no macOS tarball; mochi-mqtt ships no binaries).
  Adding an unverified path for one plugin would hole the mechanism every other
  plugin relies on. The README lists the three real options, one of which is the
  `nats-server` this toolchain already pins — it speaks MQTT 3.1.1 natively.
- **Channel names are translated to topic hierarchies** (`.` → `/`), reversibly;
  a channel already containing `/` is refused with a reason rather than mapped
  ambiguously. `MQTT_TOPIC_SEPARATOR=` disables it.
- **A dead broker costs one connect timeout per cooldown**, not one per publish.
  Without that, a broker outage under PHP-FPM fills the pool with processes
  blocked in `connect()`.
- **`0x8E Session taken over` is not retried.** Retrying starts a fight with
  whatever process took the identifier, and the two evict each other
  indefinitely.

### Found by running against a real broker

Five bugs passed the whole 256-test in-memory suite and surfaced within minutes
against `nats-server`. Each is pinned in `tests/RealBrokerRegressionTest.php`.

- **Retained messages were all being lost.** A broker sends one immediately
  after the SUBACK, often in the same TCP segment; the subscription was recorded
  only after the SUBACK, so the message found no handler and was dropped.
- **Unsubscribing was broken on MQTT 3.1.1.** §3.11: "The UNSUBACK Packet has no
  payload." The decoder required a reason code, which is a 5.0 rule.
- **A PUBLISH may carry several Subscription Identifiers** (§3.3.2.3.8). The
  duplicate-property check rejected the second as a Protocol Error and closed
  the connection.
- **A 3.1.1-only broker answers a 5.0 CONNECT in the 3.1.1 shape.** This was
  reported as a corrupt property block; it now says the broker does not
  implement 5.0 and names `MQTT_VERSION=3.1.1`.
- **The ping interval floor removed the margin** that 80% of the keep-alive
  exists to provide, so a one-second keep-alive was dropped by the broker before
  a PINGREQ went out.

A sixth came from running the commands rather than the tests, and is not pinned
by one:

- **`mqtt:status` printed a configuration it was not using.** It resolved the
  options twice, and because a client identifier is GENERATED, the second call
  produced a different one — so it printed one id, connected with another, and
  reported the difference as the broker having assigned one.
  `MqttFactory::fromOptions()` now exists so options are resolved once.

### Not verified

- **MQTT 5.0 has not been run against a real broker.** The 3.1.1 path was
  verified end to end against `nats-server`; 5.0 — the default — is covered only
  by hand-built fixtures and a local stub. Running the Broker suite with
  `MQTT_TEST_VERSION=5` against mosquitto or EMQX is the gap worth closing
  first.
- No enhanced authentication (`AUTH`); a broker that offers it is refused with
  an explanation.
- Topic aliases are decoded but never sent.
- No subscription-identifier routing, so overlapping filters on one connection
  may call a handler more than once per message on brokers that send one copy
  per matching subscription.
- No load test.
