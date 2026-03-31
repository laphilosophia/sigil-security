# Documentation Index

Sigil now has two documentation layers:

- practical onboarding docs for application developers
- deeper specification and operations docs for implementers and reviewers
- human-authored package and API guides where generated docs would be too noisy

## Start Here

- [Root README](../README.md): package overview, install, first runtime example
- [Quickstart](./QUICKSTART.md): fastest path to a working server integration
- [Implementation Plan](./IMPLEMENTATION_PLAN.md): released status, completed phases, and remaining roadmap work

## Package Guides

- [@sigil-security/core](../packages/core/README.md)
- [@sigil-security/policy](../packages/policy/README.md)
- [@sigil-security/runtime](../packages/runtime/README.md)
- [@sigil-security/client](../packages/client/README.md)
- [@sigil-security/ops](../packages/ops/README.md)

## Architecture And Security Docs

- [Boundary Specification](./BOUNDARY_SPECIFICATION.md): non-negotiable layer boundaries
- [Specification](./SPECIFICATION.md): token model, lifecycle, validation flow
- [Operations Manual](./OPERATIONS.md): monitoring, anomaly response, incident handling
- [Crypto Analysis](./CRYPTO_ANALYSIS.md): WebCrypto choices and constraints
- [Security Advisories](./SECURITY_ADVISORIES.md): third-party and adapter-related security notes
- [Benchmarking](./BENCHMARKING.md): current benchmark harness and local baseline
- [Model Generalization](./MODEL_GENERALIZATION.md): longer-term positioning beyond classic CSRF framing

## Suggested Reading Paths

### Application teams

1. [Root README](../README.md)
2. [Quickstart](./QUICKSTART.md)
3. [Runtime README](../packages/runtime/README.md)
4. [Client README](../packages/client/README.md) if browser helpers are needed
5. [Ops README](../packages/ops/README.md) if telemetry is needed

### Security reviewers

1. [Boundary Specification](./BOUNDARY_SPECIFICATION.md)
2. [Specification](./SPECIFICATION.md)
3. [Operations Manual](./OPERATIONS.md)
4. [Security Advisories](./SECURITY_ADVISORIES.md)
5. [Benchmarking](./BENCHMARKING.md)

### Contributors

1. [Implementation Plan](./IMPLEMENTATION_PLAN.md)
2. [Boundary Specification](./BOUNDARY_SPECIFICATION.md)
3. package README for the area being changed
4. [Specification](./SPECIFICATION.md)
