# Security FAQ

This FAQ answers the most common security and adoption questions about Sigil.

It is written for application teams, reviewers, and maintainers who want the plain-language version of Sigil’s security model without reading the full specification first.

## What problem does Sigil solve?

Sigil protects state-changing web requests by combining:

- cryptographic token integrity
- request provenance checks such as Origin and Fetch Metadata
- freshness limits such as TTL
- optional replay resistance via one-shot tokens

In short, Sigil is designed to answer:

> "Is this mutation request authentic, fresh, and contextually valid?"

## Is Sigil just a CSRF library?

Not exactly.

CSRF protection is one important use case, but the project is intentionally framed as a stateless cryptographic request intent verification primitive. That broader framing matters because the design combines token integrity, provenance, context, and freshness rather than treating a token by itself as the whole defense.

Still, if your immediate goal is "protect browser-authenticated state-changing requests", thinking of Sigil as a strong modern CSRF system is perfectly reasonable.

## Does Sigil prevent XSS?

No.

If an attacker can run JavaScript in-origin, they may be able to:

- request fresh tokens
- reuse valid browser credentials
- invoke protected endpoints legitimately from the compromised origin

Sigil helps with cross-site request forgery and related request-integrity problems. It does not replace XSS prevention, content security policy, secure templating, output encoding, or browser hardening.

## Does Sigil eliminate replay attacks completely?

No, not in the absolute sense.

Regular tokens are still bounded by a TTL window. That means replay is constrained, not universally impossible. This is an intentional tradeoff in stateless designs.

Sigil reduces replay exposure by combining:

- token expiry windows
- optional context binding
- Origin / Fetch Metadata validation
- optional one-shot tokens for high-assurance actions

If you need stronger replay resistance for a specific action, use one-shot tokens there instead of trying to make every request single-use.

## What do one-shot tokens actually add?

One-shot tokens are action-bound and intended for a single successful use.

They are most useful for:

- destructive account operations
- password or credential changes
- payout, transfer, or irreversible actions
- privileged admin actions

They are usually unnecessary for every normal CRUD mutation. The project is intentionally designed so teams can apply one-shot selectively where the assurance payoff is worth the extra flow.

## If Sigil is stateless, what state exists at all?

The main token model is stateless.

The main exception is the in-memory nonce cache used for one-shot replay detection. That cache is:

- bounded
- ephemeral
- local to the instance
- non-persistent

This means one-shot replay resistance is practical and useful, but it is not a distributed, globally shared replay ledger.

## What happens if the nonce cache fails?

The design goal is to fail in a way that does not break valid traffic unnecessarily.

For one-shot support, the nonce cache is an optimization with bounded guarantees, not a full distributed consistency system. The core package does not rely on Redis or a database for this because that would expand the core beyond its intended boundary.

If you need distributed replay semantics across many nodes, that is a separate system design problem and should not be pushed into `core`.

## Why are client-facing errors generic?

To avoid turning failures into an oracle.

Sigil intentionally avoids telling the client whether the failure was caused by:

- a malformed token
- an invalid MAC
- an expired token
- a context mismatch
- a provenance policy failure

The client gets a generic error body, while detailed failure reasons remain internal. That reduces the usefulness of probing attacks and keeps the public contract simple.

## Then how does the browser know a token expired?

Sigil can communicate expiry hints through headers without exposing a full failure taxonomy in the response body.

This supports browser refresh behavior while still keeping the body generic.

## Does Sigil replace authentication or authorization?

No.

Sigil does not decide:

- who the user is
- what the user is allowed to do
- whether a session is valid
- what roles or scopes the request has

Authentication and authorization still belong to your existing identity and access control systems.

Sigil verifies the integrity and context of the request, not the business legitimacy of the actor.

## Should every project use `@sigil-security/client`?

No.

Many teams can start with:

- `@sigil-security/runtime`
- a token endpoint
- a simple browser fetch step that attaches the token

Use `client` when the browser-side lifecycle becomes complex enough to justify:

- silent refresh
- multi-tab sync
- fetch wrapping
- one-shot helper flows

`client` is implemented and tested, but still explicitly experimental.

## Should every project use `@sigil-security/ops`?

No.

`ops` is useful when you are ready to wire:

- metrics
- anomaly signals
- structured security logs

If you are still getting the protection model integrated, `runtime` alone is often enough at first. `ops` is also still explicitly experimental.

## Why not put everything into one package?

Because the boundaries are part of the security and maintenance model.

Sigil keeps:

- crypto in `core`
- request policy in `policy`
- framework integration in `runtime`
- browser behavior in `client`
- observability in `ops`

That separation helps with:

- auditability
- scope control
- testability
- avoiding framework-specific sprawl in the security primitive

## Why are Oak and Hono not currently shipped?

They were intentionally kept out of the supported runtime surface pending separate security review and remediation confidence.

This is a risk-reduction decision, not an omission by accident. The project currently prefers a narrower trusted integration surface over a broader but less certain one.

See [SECURITY_ADVISORIES.md](./SECURITY_ADVISORIES.md) for the current support note.

## What is the minimum safe production starting point?

For most teams:

1. use `@sigil-security/runtime`
2. configure a strong `masterSecret`
3. set `allowedOrigins` correctly
4. expose `GET /api/csrf/token`
5. protect real state-changing routes
6. add one-shot only to high-assurance routes

That gives a strong baseline without overcomplicating the rollout.

## How strong does the master secret need to be?

Treat it like real key material.

At minimum, use at least 32 bytes of strong entropy. Do not use short human-memorable strings or weak environment defaults. The strength of the key hierarchy is bounded by the strength of the master secret.

## Does Sigil require sessions, Redis, or sticky load balancing?

No for the regular token model.

That statelessness is one of the core design goals. One-shot replay handling uses only bounded in-memory state and does not force the whole system into a session-store architecture.

## What are the main tradeoffs of the design?

The main tradeoffs are:

- regular tokens are time-bounded rather than universally single-use
- one-shot replay guarantees are bounded by local ephemeral cache semantics
- stronger assurance sometimes means slightly more integration complexity
- the project deliberately keeps some optional surfaces experimental instead of over-promising maturity

These are intentional choices, not accidental gaps.

## What should a security reviewer read first?

Recommended order:

1. [BOUNDARY_SPECIFICATION.md](./BOUNDARY_SPECIFICATION.md)
2. [SPECIFICATION.md](./SPECIFICATION.md)
3. this FAQ
4. [OPERATIONS.md](./OPERATIONS.md)
5. [SECURITY_ADVISORIES.md](./SECURITY_ADVISORIES.md)
6. [BENCHMARKING.md](./BENCHMARKING.md)

## What should an application team read first?

Recommended order:

1. [README.md](../README.md)
2. [QUICKSTART.md](./QUICKSTART.md)
3. [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md)
4. this FAQ

## What is the simplest way to think about Sigil?

Think of it as a layered answer to this question:

> "Should this state-changing request be trusted enough to execute?"

If you keep that framing in mind, the package boundaries and integration choices become much easier to reason about.
