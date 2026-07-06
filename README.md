# Elide

Elide is a log-structured block storage system combining demand-fetch, content-addressed dedup, and delta compression, designed for running many VMs efficiently on shared infrastructure.

## Documentation

- **Start here** — [quickstart.md](docs/quickstart.md) (Fly.io + Tigris), then [overview.md](docs/overview.md); local-build guides in [quickstart-local.md](docs/quickstart-local.md), [quickstart-data-volume.md](docs/quickstart-data-volume.md), and [quickstart-tigris.md](docs/quickstart-tigris.md)
- **Concepts & reference** — architecture, formats, operations, testing, findings, reference, and prior-art comparisons, all in [docs/](docs/)
- **Design notes** — [docs/design/](docs/design/)
- **Implementation plans** — [docs/plans/](docs/plans/)
- **Status updates** — [docs/status/](docs/status/)

## Continuous integration

Two lanes run unconditionally on every pull request and every push to `main`:

- `ci` — build, clippy, and userspace tests.
- `ci-kernel` — kernel-dependent features (`ublk::`) exercised inside
  a nested KVM VM on the GitHub runner. Host builds the test binary; the guest
  runs it via a 9p share. Blocking, not advisory.
