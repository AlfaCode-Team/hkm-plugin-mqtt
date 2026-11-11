# hkm-plugin-mqtt — `pubsub.mqtt`

A native MQTT **3.1.1 and 5.0** client, and the kernel's `PubSubPort` over it.
No MQTT library.

```php
// app/bootstrap/base.php
use Plugins\Mqtt\Infrastructure\Adapters\MqttFactory;

->withPorts([
    PubSubPort::class => MqttFactory::fromEnv(),
])
```

```bash
hkm cli mqtt:status                      # dial for real and report what came back
hkm cli mqtt:listen 'documents/+'        # a tap on the broker
hkm cli mqtt:publish documents/42 '{"title":"renamed"}'
```

---

## Read this before you set `MQTT_CLIENT_ID`

MQTT's client identifier is **an exclusive lock on a broker-wide name, and
connecting steals it.**

> **[MQTT-3.1.4-3]** If the ClientID represents a Client already connected to
> the Server, the Server sends a DISCONNECT packet to the existing Client with
> Reason Code `0x8E` (Session taken over) … and MUST close the Network
> Connection of the existing Client.

So set `MQTT_CLIENT_ID=hkm` — the obvious thing, and what every broker's
quickstart shows — and deploy a realtime server plus a PHP-FPM pool:

1. The realtime server connects as `hkm` and subscribes. Everything works.
2. An HTTP request arrives. Its worker connects as `hkm` to publish.
3. **The broker evicts the realtime server**, which loses its subscriptions.
4. The publish succeeds. The HTTP response is 200. Nothing is logged.
5. The realtime server reconnects — and evicts the next publisher.

Two processes fight over one name for ever, each reconnecting constantly, with
messages delivered or dropped depending on who happens to hold the lock. **Every
individual operation reports success.** Under one worker in development the
window is small enough to miss entirely.

**So leave `MQTT_CLIENT_ID` unset.** Each process then derives its own — 23
bytes, alphanumeric, inside the set `[MQTT-3.1.3-5]` requires every broker to
accept. A fixed id is correct for exactly one case, a single supervised
subscriber that wants the broker to hold its session across a restart, and
`mqtt:status` warns whenever one is configured.

The subscriber also refuses to retry into that fight: on `0x8E` it stops with an
error that names the cause, because retrying is what turns one mistake into two
processes evicting each other indefinitely.

---

## Why MQTT when `pubsub.nats` already solves fan-out

Because the other end is often not yours. NATS is an excellent internal bus and
nothing speaks it but NATS clients. MQTT is what devices, gateways and managed
IoT brokers speak — so this is for joining a conversation you do not control.

It also brings three things a NATS-core bus structurally cannot:

| | |
|---|---|
| **QoS 1 and 2** | a publisher can know the broker took the message, and at QoS 2 that it took it exactly once |
| **Retained messages** | a subscriber arriving late gets the current value of a topic instead of waiting for the next change |
| **Wills** | the broker announces this process's disappearance on its behalf — which nothing a dead process could do would achieve |

Both plugins implement the same `PubSubPort`, so a project binds **one** of them.

---

## Getting a broker

**This plugin declares no `daemon` block, and that is deliberate.** The kernel's
`daemon:install` mechanism pins a SHA-256 per platform and refuses a platform it
has no digest for — which needs a broker that publishes one verifiable archive
per platform. Checked, and none does:

| | |
|---|---|
| mosquitto | cuts no GitHub releases at all |
| NanoMQ | linux `.deb`/`.rpm` only — no darwin, no `tar.gz` |
| EMQX | no macOS tarball in its releases |
| mochi-mqtt | ships no binaries |

Adding an unverified download path for this one plugin would put a hole in the
mechanism every other plugin relies on. So: three real options.

**1. The broker you already run.** Most MQTT deployments have one, often managed
(AWS IoT, HiveMQ Cloud, EMQX Cloud). Point `MQTT_URL` at it.

**2. `nats-server`, which this toolchain already pins.** It speaks MQTT 3.1.1
natively, so a project running the NATS plugin adds a *listener* rather than a
second daemon. It needs JetStream for MQTT session state:

```
jetstream { store_dir: "./var/daemon/nats-server/js" }
mqtt {
  host: "127.0.0.1"
  port: 1883
}
```

Without JetStream it refuses to start, in as many words:
`mqtt requires JetStream to be enabled if running in standalone mode`.

**It is MQTT 3.1.1 only — set `MQTT_VERSION=3.1.1`.** Sent a 5.0 CONNECT it
answers return code 1, "unacceptable protocol version", and this client reports
exactly that rather than a confusing parse error.

**3. Your platform's package manager**, for mosquitto. Fine for development; it
is simply not something the digest-pinning mechanism can install.

---

## What it does and does not promise

`PubSubPort` promises **at-most-once** delivery, which is QoS 0, and the adapter
publishes and subscribes at QoS 0 for exactly that reason. Promising more
through that interface would be a promise the Redis and NATS-core adapters could
not keep.

QoS 1 and 2, retained messages, wills, shared subscriptions and the MQTT 5.0
properties are reached through the native client, where a caller can see what it
is buying:

```php
// A module that declares `pubsub.mqtt` in its requires[]
$client = $container->make(\Plugins\Mqtt\Application\Services\MqttClient::class);

$ack = $client->publish('orders/42/paid', ['total' => 1999], QoS::AtLeastOnce);

if ($ack?->reasonCode->isSilentNoOp()) {
    // 0x10 No matching subscribers: accepted, and nobody was listening.
    // A SUCCESS that lost the message, and below the 0x80 error boundary —
    // so a caller checking only for errors never sees it.
}
```

It is resolved **from the bound port**, never constructed, so it shares the one
connection this worker holds. For MQTT that is not merely tidier: a second
connection would need its own client identifier, or it would evict the first.

### Channel names become topic hierarchies

The kernel's channels are dotted (`documents.42`); MQTT's topics are slashed.
A dot is a legal topic character, so passing it through would *work* — and would
collapse the hierarchy, and with it every wildcard, since `documents/+` cannot
match a topic with no levels in it.

So `.` becomes `/` by default, and the mapping is **reversible**: a subscriber is
handed the channel name the publisher used. That constrains it — a channel
already containing `/` would be indistinguishable in the topic from a translated
separator, so it is **refused with a reason** rather than guessed. Set
`MQTT_TOPIC_SEPARATOR=` to pass channel names through verbatim.

### Overlapping filters on one connection

A broker may send one copy of a message per matching subscription or a single
copy, and `[MQTT 3.3.4]` permits both. This client calls **every matching
handler for every copy**, so two overlapping filters on one connection can mean
a handler runs more than once per message — on nats-server it does, on mosquitto
it does not. MQTT 5.0's subscription identifiers exist to resolve this; this
client decodes them (including several on one PUBLISH) but does not yet route by
them. Prefer non-overlapping filters per connection.

---

## Config

| Env | Default | |
|---|---|---|
| `MQTT_URL` | `mqtt://127.0.0.1:1883` | comma-separated for failover; `mqtts://` or port 8883 implies TLS |
| `MQTT_CLIENT_ID` | *(generated per process)* | **read the warning above before setting this** |
| `MQTT_CLIENT_ID_PREFIX` | `hkm` | up to 3 chars of the generated id, for a human reading the broker's client list |
| `MQTT_USER` / `MQTT_PASS` | — | the password is Binary Data, so it may contain non-UTF-8 bytes |
| `MQTT_VERSION` | `5` | or `3.1.1`. The wire format differs; a typo is refused, not defaulted |
| `MQTT_KEEP_ALIVE` | `60` | seconds. A PINGREQ goes out at 80% of this — the only thing keeping an idle subscription alive |
| `MQTT_CLEAN_START` | `true` | off needs a FIXED client id, and is refused with a generated one |
| `MQTT_SESSION_EXPIRY` | `0` | seconds the broker holds a session; 5.0 only |
| `MQTT_QOS` | `0` | the port's own publishes; 0 is what `PubSubPort` promises |
| `MQTT_RETAIN` | `false` | a retained message outlives the publisher, indefinitely |
| `MQTT_TOPIC_PREFIX` | — | prepended to every topic; keeps an app off a shared broker's root |
| `MQTT_TOPIC_SEPARATOR` | `.` | the channel-name character that maps to MQTT's `/`; **empty disables translation** |
| `MQTT_SHARE_NAME` | — | `$share/<name>/` — queue semantics, NOT fan-out. 5.0 only |
| `MQTT_TLS` | `auto` | `auto` reads the scheme and port; `require` for a TLS broker on another port |
| `MQTT_TLS_CA` | — | a bundle file or a directory, for a private CA |
| `MQTT_TLS_INSECURE` | `false` | accepts ANY certificate — encrypted against a passive observer, open to an active one |
| `MQTT_CONNECT_TIMEOUT` | `5` | seconds |
| `MQTT_READ_TIMEOUT` | `5` | seconds; also bounds shutdown latency |
| `MQTT_MAX_PACKET_BYTES` | `8388608` | the declared length is refused above this BEFORE the body is buffered |
| `MQTT_MAX_RECONNECTS` | `10` | 0 disables reconnection |
| `MQTT_RECONNECT_WAIT` | `2` | seconds; exponential, capped, jittered |
| `MQTT_FAILURE_COOLDOWN` | `30` | seconds a dead broker costs ONE timeout rather than one per publish |
| `MQTT_WILL_TOPIC` | — | set to enable a will; the four below are read only then |
| `MQTT_WILL_PAYLOAD` / `MQTT_WILL_QOS` / `MQTT_WILL_RETAIN` / `MQTT_WILL_DELAY` | — | `MQTT_WILL_DELAY` is 5.0 only |

### TLS cannot be stripped here, unlike NATS

The NATS plugin's `TlsMode` carries a warning: NATS negotiates TLS in the clear,
so its `tls_required` flag is an instruction an attacker on the path can clear,
after which the client continues in plaintext and sends its password.

**MQTT has no in-band TLS negotiation at all.** The client speaks first, and the
socket either was TLS or was not — so the decision is made from local
configuration before a byte is sent, and `auto` is genuinely safe. The failure
mode of pointing a plaintext client at a TLS listener is loud, and this client's
timeout message names it as the likely cause.

---

## Tests

```bash
vendor/bin/phpunit --testsuite Protocol    # 256 tests, no sockets
vendor/bin/phpunit --testsuite Socket      #  11 tests, real TCP + TLS, a stub in a second process

# The only non-self-referential tests. They SKIP without MQTT_TEST_URL.
MQTT_TEST_URL=mqtt://127.0.0.1:1883 MQTT_TEST_VERSION=3.1.1 \
    vendor/bin/phpunit --testsuite Broker
```

**The Broker suite earned its keep immediately, and that is the most useful
thing in this README.** Five bugs had passed the entire 256-test Protocol suite
and surfaced within minutes of pointing the client at a broker nobody here
wrote. Each is now pinned in `tests/RealBrokerRegressionTest.php`:

1. **Every retained message was being lost.** A broker sends a retained message
   immediately after the SUBACK, and the two routinely arrive in the *same TCP
   segment* — so the PUBLISH was dispatched before the subscription was
   recorded, found no handler, and was dropped. Since that is exactly when
   retained messages arrive, essentially all of them were lost, while the
   subscription reported success.
2. **Unsubscribing was broken on 3.1.1.** §3.11: "The UNSUBACK Packet has no
   payload." The decoder required a reason code — a 5.0 rule — so a broker
   behaving perfectly was called malformed.
3. **A PUBLISH may carry several Subscription Identifiers** (§3.3.2.3.8), one
   per matching subscription. The duplicate-property check rejected the second
   as a Protocol Error and closed the connection — and only for clients with
   overlapping subscriptions, so no test without two of them could have caught
   it.
4. **A 3.1.1-only broker answers a 5.0 CONNECT in the 3.1.1 shape.** The client
   reported "the CONNACK property block runs past the end of the packet", which
   sends an operator hunting a corrupt stream when the answer is one environment
   variable. It now says so and names the variable.
5. **The ping interval floor removed the whole margin.** The interval is 80% of
   the keep-alive precisely so the packet has time to travel; a floor of 1.0
   made a keep-alive of 1 second have no margin at all, and a real broker
   dropped every such connection before a PINGREQ went out.

Other tests worth their keep:

- **The topic matcher against the specification's own examples** — `sport/#`
  matches the bare `sport` because `#` includes the parent level; `sport/+` does
  *not* match `sport` but does match `sport/`; and a filter beginning with a
  wildcard never matches a `$`-prefixed topic, so `#` is **not** "everything"
  and a monitoring subscriber written against it silently sees no `$SYS`.
- **The three Variable Byte Integer hazards**: four legal bytes claiming 256 MiB
  are refused *before a single body byte is buffered*; a fifth continuation byte
  is refused rather than consuming the stream; and a non-minimal encoding is
  refused, because otherwise one value has several byte representations.
- **`U+0000` is valid UTF-8 and still forbidden** — `mb_check_encoding("\x00")`
  is `true` on this build, measured, which is why the NUL check is separate and
  first.
- **The fixed-header flags are verified inbound as well as emitted correctly.**
  SUBSCRIBE, UNSUBSCRIBE and PUBREL require `0b0010`, not `0b0000`; a SUBSCRIBE
  with zero there is not answered with an error — the broker closes the socket,
  which a client reads as a network failure and retries, for ever.
- **Inbound QoS 2 is exactly-once.** A re-sent PUBLISH is PUBREC'd again but
  *not* delivered again, which is the only thing separating QoS 2 from QoS 1
  with extra round trips.
- **A payload of 512 KiB over a real socket**, to prove the write loop sends
  every byte: a truncated packet in a length-prefixed protocol is not a
  recoverable error but a permanent desynchronisation.
- **A self-signed certificate is refused when verifying**, which demonstrates
  what `MQTT_TLS_INSECURE` costs rather than describing it.

### What is NOT verified

- **MQTT 5.0 has not been run against a real broker.** The 3.1.1 path was
  verified end to end against `nats-server` — handshake, QoS 1, QoS 2, retained
  messages, wildcards, will, keep-alive, eviction, persistent session. The 5.0
  path is covered only by hand-built fixtures and the local stub, because no
  5.0 broker was available here. **5.0 is the default**, so this is the gap worth
  closing first: run the Broker suite with `MQTT_TEST_VERSION=5` against
  mosquitto or EMQX.
- **No enhanced authentication** (the `AUTH` packet, SCRAM and friends). A
  broker that sends `AUTH` is refused with an explanation rather than left
  waiting for a reply this client will never send.
- **Topic aliases are decoded but never sent.** This client advertises no Topic
  Alias Maximum, so a broker must not use them, and a PUBLISH with an empty
  topic is refused rather than resolved against a mapping that does not exist.
- **No subscription-identifier routing** — see "Overlapping filters" above.
- **No load test.** Nothing here measures throughput or connection count.
