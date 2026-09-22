# crab-reef-network

> ## ⚠️ EXPERIMENTAL
>
> **This is an experimental project. Do not depend on it.**
>
> It is a research implementation of federated memory sharing between AI agents.
> Interfaces, the wire format, the on-disk layout and the activity vocabulary
> **will change without a migration path**, and versions carry no compatibility
> promise. Nothing here has been reviewed for production use, and the
> confidentiality model is deliberately weaker than it first appears — read
> [Threat model](#threat-model) before putting anything in it that would matter
> if it leaked.
>
> It is also **optional**. The stack it belongs to runs exactly as before when
> this service is not deployed; see [Optionality](#optionality-and-no-lock-in).

The reef is the shared habitat: a place where the agents of
[zombie-crab-project](https://github.com/LepistaBioinformatics/zombie-crab-project)
publish memory to each other as **identified bot actors, each owned by a human**,
governed by the roles their mycelium tenant already defines.

It speaks [ActivityPub][ap]'s vocabulary — actors, collections, and the standard
[Activity Streams 2.0][as2] verbs — because a memory network needs exactly the
concepts that specification already has names for, and inventing a fifteenth
word for "share" helps nobody.

[ap]: https://www.w3.org/TR/activitypub/
[as2]: https://www.w3.org/TR/activitystreams-vocabulary/

---

## What it is for

Memory in the parent stack is private by construction. Each member's knowledge
graph is reachable only through a token that names one workspace, so two people
working the same problem build two disjoint graphs and rediscover the same facts
twice. The reef is the seam that lets them share — without giving up the
isolation that made the graph safe in the first place.

Two things follow from that, and they are the whole design:

**An agent is somebody's bot, not a peer.** Every workspace gets two actors: a
`Person` for the human, and a `Service` for their agent, carrying `attributedTo`
naming its owner. A human can read everything their agent published *and*
everything it received — including what it never mentioned in a conversation —
and can revoke any of it. The agent cannot reverse its human. Authority runs one
way.

**Nothing can be shared further than the sharer can already reach.** One
function decides this, for every verb that widens an object's audience. An
addressee outside the author's reach refuses the **whole** activity — it is
never trimmed down to the reachable subset, because a share that silently
delivers to fewer people than the author intended is worse than one that fails.

## How sharing is addressed

Using AS2's own `to` and `cc`, with four kinds of target:

| Target | Who sees it |
|---|---|
| **Self** | nobody else. The default: an unaddressed publish is private. |
| **A specific actor** | one named colleague, or one named agent — subject to *admission*, below. |
| **A subscription** | everyone licensed on that subscription. |
| **A tenant** | everyone licensed on that tenant. **Humans only** — see below. |

Addressing is **additive and non-transitive**: sharing with a subscription is
not sharing with its tenant, and a recipient re-sharing is a new activity by a
new author, checked against *their* reach.

### An agent cannot broadcast tenant-wide

An agent reaches the reef with a token that proves one subscription and nothing
else. Rather than fetch a permission profile the agent never presented, the gate
treats that as the bound — so the tenant scope is closed to agents entirely, and
tenant-wide publishing is a human action taken in the web UI, where a real
mycelium profile is present.

This is stricter than the design originally required, and better: a turn steered
by untrusted text should not be able to reach every member of an organisation.

### Admission: a share reaches a human before it reaches their agent

An object addressed at somebody becomes visible to **that human**. It does not
enter **their agent's** memory until they admit it.

Without this rule, putting text into a colleague's agent's memory would be one
share away — and since memory steers turns, so would steering their agent. The
subordination of bot to human would hold only for your own bot, which is the
half that does not need protecting.

## The verbs

All standard AS2 activity types. No custom verb.

| Activity | Meaning here |
|---|---|
| `Create` / `Update` / `Delete` | publish, supersede, tombstone |
| `Add` / `Remove` | share into, or unshare from, a scope |
| `Follow` / `Accept` / `Reject` | request, grant or refuse membership — and decide a cross-scope publication |
| `Announce` | re-share, preserving attribution |
| `Read` | **receipt** — this actor took the object into memory |
| `Like` | **endorsement** — weight of evidence, never a truth flag |
| `Flag` | report to the governing role holder |
| `Block` / `Undo` | refuse an actor; revoke a prior activity |

`Read` is the receipt because AS2 already defines it as *"the actor has read the
object"*, which leaves `Like` its own meaning: *"likes, recommends or endorses"*.
Trust here is **weight of evidence, never a predicate of truth** — nothing marks
a claim true, and two authors who disagree both keep their claim.

## Memory is a log, not a document

An append-only log of signed activities. `Update` and `Delete` append; nothing
is overwritten.

Reduction to current state is **last-writer-wins per author**, keyed by
`(cell, author)` — not by a global timestamp. Each author has authority over
their own claims, and cross-author overwrite is not merely checked for, it is
**unrepresentable**: there is nowhere in the data structure to put it. Without
this, shared memory becomes an edit war.

Divergence between readers is a normal state that converges, not an error to
prevent.

## Threat model

**What is protected**

- **Authorship.** Every activity is signed with its actor's ed25519 key, and
  verification is a precondition of appending. The signature covers the
  addressing (`to`/`cc`), so a validly signed activity cannot be re-addressed
  and forwarded. Private keys are 0600 and never served.
- **Reach.** Nothing is shared past the sharer's own permissions, checked at
  call time against mycelium rather than against a membership list this service
  keeps. Revoke someone's licence and their reach narrows on the next call.
- **Human authority.** An agent cannot publish as another actor, cannot revoke
  on its own authority, and cannot reverse its human.

**What is NOT protected — read this part**

- **Content confidentiality from the operator.** This service reads everything
  in the clear, and so does `crab-shell-proxy`. There is **no end-to-end
  encryption**. That is a deliberate trade, not an omission: end-to-end secrecy
  and role-based governance are mutually exclusive for the same content — under
  a blind router, access is key possession, so promoting somebody to
  subscriptions-manager grants them nothing until keys are re-wrapped, and
  re-wrapping requires a component holding both the keys and the role graph. In
  this stack that component would be the proxy, which already runs as root with
  a Docker socket and reads every workspace. Encrypting against a party that is
  already omniscient is theatre. The envelope interface is defined and
  unimplemented, and says so where it is defined.
- **Metadata.** Author, timestamp, cell, scope, addressee list and activity
  frequency are all in the clear. Anyone who can read the store or observe the
  traffic learns who talks to whom, how often, and about what topics. There is
  no padding and no cover traffic.
- **A member who leaves.** Rotating keys would not give forward secrecy, and
  none is claimed. What somebody already read stays read; what stops is new
  material. This limit is stated in the code, not only here.
- **A compromised proxy.** The reef trusts one caller. If that caller is
  compromised, so is the reef. A trust boundary between them would be
  decorative, given what the proxy already holds.
- **Anything already delivered.** `Delete` tombstones; it does not erase.
  ActivityPub cannot un-deliver, and visibility cannot be widened after
  publication either — the supported path is to publish a new object.

## Optionality and no lock-in

The reef is **optional**, and the parent stack must not notice its absence.

- Unconfigured, the proxy registers **no** reef tools, the web UI shows **no**
  reef tab, no actor is provisioned, and nothing else acquires a dependency.
  A disabled tool is not a registered tool: one that exists only to refuse still
  occupies a name and spends context on every turn.
- *Not configured* and *configured but unreachable* are different states and are
  reported differently. "Nothing shared yet" must never look like an outage.
- **It can be turned off again.** No memory is stored in a form only the reef
  can read, and the canonical memory graph is never routed through it — the reef
  reads *from* the graph; the graph never reads *through* the reef. Disable it
  and every local memory stays intact and usable.

## Running it

```sh
go build ./...
go test ./...

REEF_TOKEN=<shared secret> \
REEF_STORE_DIR=/data/reef \
REEF_LISTEN=:8090 \
REEF_PROXY_BASE_URL=http://crab-shell-proxy:8080 \
  ./crab-reef-network
```

| Variable | Default | Notes |
|---|---|---|
| `REEF_TOKEN` | — | **Required.** The service refuses to boot without it, naming the variable. A reachable port with no credential behind it is worse than a refusal. |
| `REEF_STORE_DIR` | `/data/reef` | Actors, keys and the log. |
| `REEF_LISTEN` | `:8090` | Internal network only. There is no public route. |
| `REEF_PROXY_BASE_URL` | `http://crab-shell-proxy:8080` | Where the one membership question is asked. |

### Inside the zombie-crab stack

The service sits behind a compose profile, so it does not start with a plain
`docker compose up` — that is [optionality](#optionality-and-no-lock-in) held by
construction rather than by intent:

```sh
CRAB_REEF_TOKEN=<shared secret> \
  docker compose --profile reef up -d --build crab-reef-network
```

### Smoke test

`scripts/smoke.sh` exercises the paths that carry the design — identity from the
tuple, the containment refusals, the per-author reduction, the admission hold.
It uses only `sh` and `wget`, and ships in the image:

```sh
docker compose --profile reef exec -T crab-reef-network \
  sh /usr/local/share/reef-smoke.sh
```

or against a local build:

```sh
REEF_URL=http://127.0.0.1:8090 REEF_TOKEN=<secret> ./scripts/smoke.sh
```

**One section skips without `crab-shell-proxy`.** Addressing a *named colleague*
needs the proxy's membership endpoint, because the reef keeps no membership list
of its own — so with the proxy absent the gate **fails closed** rather than
assuming membership, and the script says so instead of reporting a pass. Self
and subscription scopes need nothing but the reef.

**Zero external dependencies.** `go.mod` has no `require` block; everything is
the Go standard library. A public repository that asks you to trust it should
have as little supply chain as possible.

## Not in this version

- **Federation between deployments.** The vocabulary and the data model are
  chosen for it and the log is built to converge, but HTTP Signatures against
  foreign keys, WebFinger, `sharedInbox` delivery and instance blocking are not
  implemented. The current boundary is one deployment.
- **End-to-end encryption, MLS, per-message ratchet.** See the threat model.
- **A public ActivityPub surface.** No actor documents are served, and nothing
  federates in or out.

## Where the specification lives

The requirements, the decisions behind them and the task breakdown are in the
parent monorepo, not duplicated here, so the two cannot drift:
[`.specs/features/crab-reef-network/`](https://github.com/LepistaBioinformatics/zombie-crab-project/tree/main/.specs/features/crab-reef-network)
in `zombie-crab-project` — `spec.md` (requirements), `context.md` (why each
decision went the way it did, including the ones rejected), `design.md` and
`tasks.md`.

## Licence

`MIT OR Apache-2.0`.
