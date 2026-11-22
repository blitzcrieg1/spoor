# Contributing to Spoor

Start with an [open issue](https://github.com/blitzcrieg1/spoor/issues) or open
one with a short description of the change you want to make. Issues labeled
`good first issue` have a small, defined scope.

## Set up and test

Fork and clone the repository. Use stable Rust with Cargo and Python 3.10 or
newer. On Debian or Ubuntu, install `build-essential`, `pkg-config`,
`libssl-dev`, and `openssl` for the Rust build and loopback TLS tests.

Run these commands from the repository root.

```sh
cargo test --locked --manifest-path rust/Cargo.toml --workspace
python scripts/run_synthetic_trace.py
python -m pip install PyYAML==6.0.3
python scripts/evaluate_lab_sigma.py
```

The synthetic trace uses a local collector and harmless fixtures. For changes
to the Linux worker, follow the [pilot instructions](README.md#isolated-linux-worker-pilot)
on a Linux host with Docker.

## Open a pull request

Create a branch in your fork and open a PR against `main`. Explain the change,
link any related issue, and list the checks you ran. GitHub may ask a maintainer
to approve the first CI run from a fork.

Use synthetic data in examples and reports. Follow the
[security policy](SECURITY.md) to report vulnerabilities privately.
