# <img src="assets/spoor-mark.svg" width="48" height="48" align="middle" alt=""> Spoor

**Follow an ARTEX tool call from policy decision to audit evidence.**

[![Rust workspace](https://img.shields.io/badge/Rust-workspace-CE422B?logo=rust&logoColor=white)](rust/Cargo.toml)
[![CI on Linux and Windows](https://github.com/blitzcrieg1/spoor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/blitzcrieg1/spoor/actions/workflows/ci.yml)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache--2.0-2563EB)](LICENSE)
[![Agentmetry ingest verified](https://img.shields.io/badge/Agentmetry-ingest_verified-087F73)](#verification)

An ARTEX worker asks to run a tool. Spoor can show what it requested, whether
policy allowed it, and what the tool reported afterward. It's an experimental
Rust broker and audit bridge for calls instrumented in a controlled lab.

Microsoft and the FBI documented ARTEX use in real intrusions in November 2026.
Spoor gives defenders a small, reproducible way to study the tool-call evidence
an instrumented agent can leave. [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/) · [FBI advisory](https://www.ic3.gov/CSA/2026/261113.pdf)

[Try a synthetic trace](#try-a-synthetic-trace) ·
[Forward to Agentmetry](#forward-to-agentmetry) ·
[Explore the detections](#detection-rules) ·
[See what has been verified](#verification) ·
[Contribute](CONTRIBUTING.md)

## Where Spoor sees the call

```mermaid
flowchart TD
    Request["ARTEX tool request"] --> Shim["Spoor shim"]
    Shim -->|Request a decision| Policy{"Spoor policy broker"}
    Policy -->|Allow| Run["Shim runs the tool"]
    Policy -->|Deny or approval required| Stop["Shim stops"]
    Policy -.->|Decision record| Trail[("JSONL audit trail")]
    Run -.->|Exit report via broker| Trail
    Trail --> Watch["Spoor watcher"]
    Trail --> Trace["TraceSig export"]
    Watch --> Audit["Agentmetry payload"]
```

The broker gives each decision a call ID. An allowed tool's report uses that ID,
and Spoor keeps the original session, command, and parent metadata. On Linux the
shim samples the parent command and redacts common credential patterns.

## Try a synthetic trace

Use a stable Rust toolchain with Cargo and Python 3.10 or newer. The same
command works in PowerShell and Bash. It starts the real shim, broker, and
watcher with a loopback mock collector. Two harmless tool calls share one
session, with exit codes 0 and 7. The demo checks each decision against its
own completion, simulates a collector and retry queue outage, and checks that
strict audit refuses a call it cannot record.

```sh
python scripts/run_synthetic_trace.py
```

### Read the two events together

```mermaid
sequenceDiagram
    participant Trail as Spoor broker trail
    participant Watcher as Spoor watcher
    participant Preview as Local mock collector
    Trail->>Watcher: Both calls authorized
    Watcher->>Preview: Authorization for call A and call B
    Trail->>Watcher: Call A exits 0 and call B exits 7
    Watcher->>Preview: Completion for each call with its own exit code
    Note over Watcher,Preview: One session, two call IDs
```

Join the two phases using `tool.arguments.call_id`. Use `session_id` to group
related calls.

| Phase | Spoor event | Meaning |
| --- | --- | --- |
| `authorization` | `tool_authorized` | Policy allowed the request. Execution is pending. |
| `authorization` | `tool_denied` or `approval_request` | Policy blocked the request or required approval. |
| `completion` | `tool_called` or `tool_failed` | The shim reported exit code 0 or a nonzero exit code in `tool.arguments.exit_code`. |

## Forward to Agentmetry

Spoor's watcher sends broker events to the
[Agentmetry external ingest API](https://github.com/blitzcrieg1/agentmetry/blob/v0.13.0/docs/agentmetry-external-ingest.md).
Run Agentmetry with external ingest and audit export enabled. Spoor's
`AGENTMETRY_URL` defaults to `http://127.0.0.1:8000`. Keep this HTTP connection
on loopback in the lab. If Agentmetry requires authentication, set
`AGENTMETRY_API_KEY` securely in the watcher's environment. An Agentmetry
ingest-only token works for forwarding.

Run the watcher with the same `BROKER_DATA_DIR` as the broker. Remove
`--once` to keep it running.

```sh
cargo run --locked --manifest-path rust/Cargo.toml -p spoor -- watch --once --policy rust/policy.json
```

Agentmetry v0.13.0 stores new Spoor requests with `source.adapter=spoor`.
It records the ARTEX attribution as `source.claimed_app=artex` and uses
`source.app=unknown` for unlisted sources. Use the adapter field to find
Spoor events and the claimed app as context. For execution counts, filter on
`tool.arguments.phase=completion`. Agentmetry v0.13.0 maps both phases of an
allowed call to `action.type=tool_called`. The `source_topic` field keeps the
original event name.

The broker event pair is the verified integration. The optional model proxy
produces an `llm_turn` payload that Agentmetry v0.13.0 handles as a generic tool
event. Look for the full model-turn record in Spoor's local trail.

## Detection rules

- [Sigma](detections/sigma) covers brokered completion reports with ARTEX or
  shell parent metadata, plus web log signals such as ARTEX user agents. The
  process rule uses the phase field preserved in stored Agentmetry events.
  The [Loki backend check](detections/sigma/tests/README.md) tests all six
  fixtures against the converted query.
- [Suricata](detections/suricata/artex-lab.rules) looks for ARTEX HTTP signals
  where the relevant traffic is visible.
- [TraceSig](detections/tracesig/lab_rules.yml) looks for sequences across the
  audit trail, including scope drift and risky data movement.

Use these experimental matches as leads to investigate alongside the rest of
the event and your environment's baseline.

## Repository layout

| Path | Contents |
| --- | --- |
| `rust/spoor` | Broker, audit watcher, model request proxy, and TraceSig exporter |
| `rust/spoor-core` | Policy, event mapping, deduplication, and signal matching |
| `rust/spoor-shim` | Tool mediation and Linux parent command capture |
| `rust/policy.json` | Example policy from the local lab |
| `detections` | Experimental Sigma, Suricata, and TraceSig rules |
| `examples` | A sample broker trail |

## Verification

[CI](https://github.com/blitzcrieg1/spoor/actions/workflows/ci.yml) builds the
checkout, runs the Rust tests and this quick start, and checks the Sigma
process fixtures on Linux and Windows.

An authenticated loopback check against Agentmetry v0.13.0 read four stored
events back from its audit API. Two distinct call IDs shared one session and
each linked its authorization to its exit code and outcome. Spoor also
exported both decisions from Agentmetry's saved trail to TraceSig.

Earlier broker trails with call IDs can be read through the updated watcher.
Consumers that used `tool_called` as a policy decision should use the
authorization phase going forward.

Build and test the Rust workspace.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --workspace
cargo test --locked --manifest-path rust/Cargo.toml --workspace
```

The focused process rule fixture check uses Python and PyYAML.

```sh
python scripts/evaluate_lab_sigma.py
```

## Deployment limits

The broker listens on loopback by default and assumes a trusted client. Use
operating system and network controls for isolation. Review the example
policy, which permits unmatched commands.

The broker attempts to write and sync each decision and completion record
before responding. On Unix it also syncs the containing directory. Provision
the broker's data directory on persistent storage before starting it when
power-loss durability matters. Set `SPOOR_STRICT_AUDIT=1` to refuse otherwise
allowed calls if the decision cannot be written or synced. Audit errors are
logged in both modes. The broker rejects a completion it cannot persist and
the shim reports the failure.

If a policy regex runs out of matching steps, the broker denies the call with
`rule_id=regex-budget-exhausted`. The response, local trail, and forwarded
Agentmetry event carry that rule ID. In Agentmetry, query
`tool.arguments.rule_id` to count these denials.

The watcher holds its checkpoint when it can neither deliver an event nor
flush it to the local retry queue. A running watcher retries from the blocked
record. Queued events are replayed at startup. A single run returns an error
if it is blocked. Delivery can repeat after a restart or an ambiguous ingest
response, so consumers should handle duplicate events.

The optional HTTPS proxy uses the platform TLS trust store and keeps request
headers and bodies in memory. It connects directly to its configured upstream
and returns redirects to the caller. Linux source builds need the OpenSSL
development libraries. The Linux HTTPS test also uses the `openssl` executable
to create a temporary loopback certificate.

Audit trails can contain command arguments and model prompt content. Parent
command redaction covers common credential patterns. For audit data handling
and private vulnerability reporting, see the [security policy](SECURITY.md).

## Isolated Linux worker pilot

A trusted operator can run one offline worker through the host-side Spoor
shim. The Docker daemon, broker, and audit trail stay outside the worker.
Use a dedicated lab host or VM and an approved Linux image. Keep the launcher
and access to the Docker daemon with the operator.

The worker runs as UID and GID 65532 with a read-only root filesystem, a
16 MiB writable `/tmp`, and loopback-only networking. The launcher drops
capabilities, disallows privilege gains, and requires Docker seccomp and
resource limits. It accepts a locally available image by its full ID,
rejects images that declare volumes, and supplies no host bind mounts.

Use a stable Rust toolchain with Cargo, Python 3.10 or newer, and a running
Linux Docker daemon that your operator account can access. On Debian or
Ubuntu, install the build dependencies listed in [Contributing](CONTRIBUTING.md).
Run the commands from the repository root in both terminals.

Build the workspace and leave the host broker running in the first terminal.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --workspace
SPOOR_STRICT_AUDIT=1 rust/target/debug/spoor broker --policy rust/policy.json
```

From a second Bash terminal on the Linux host, approve the exact image,
executable, and arguments, then send the approval to the launcher on standard
input. The approval also binds the operator's Linux UID and the isolation
flags. Use a private state directory on the host. The approval expires after
five minutes and is consumed before the shim asks the broker to authorize
the launch. If a launch fails after consumption, issue a fresh approval.

```bash
docker pull python:3.12-alpine
worker_image="$(docker image inspect --format '{{.Id}}' python:3.12-alpine)"
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/spoor/worker-approvals"
request=("$worker_image" /usr/local/bin/python -c 'print("hello from the worker")')
approval="$(python3 scripts/run_isolated_worker.py approve --state-dir "$state_dir" "${request[@]}")"
printf '%s\n' "$approval" | python3 scripts/run_isolated_worker.py run \
  --state-dir "$state_dir" --shim rust/target/debug/spoor-shim "${request[@]}"
```

The worker prints `hello from the worker`. Open `data/broker-events.jsonl`, the
default broker trail, and find the matching `call_id` on the two records.
The `decide` record has `decision: allow` and the `report` record has
`exit_code: 0`. The launcher requires a broker that confirms strict audit.

The Linux CI probe checks the restrictions in a child process, approval
consumption, and both audit events. It forwards the successful launch and exit
to Agentmetry v0.13.0 and reads them back by call ID. Activity inside the
container stays subject to Docker's isolation.

### Inspect rejected approvals

The launcher records an approval rejection in the private approval database.
That record contains its UTC timestamp, the request fingerprint, and a
reason such as `approval_reused`, `approval_expired`, or
`approval_request_mismatch`. The export is JSONL with four fields, including
the event type.

```sh
python3 scripts/run_isolated_worker.py rejections --state-dir "$state_dir"
```

The rejection record omits tokens and raw arguments. Approval hashes can
identify expired or previously consumed tokens for one hour after expiry.
The launcher prunes older hashes when issuing a new approval. Rejected
approvals stop before the shim submits a broker request.

To check replay handling, repeat the `printf … | python3 … run` command in the
same terminal with the same approval. The launcher exits with status 1,
starts zero containers, and adds one `approval_reused` record. The broker
trail keeps the original decision and completion pair. When you finish, stop
the broker with Ctrl+C in the first terminal.

### Measure launch latency

On the Linux worker host, reuse the local Python image ID from the quickstart.

```sh
python3 scripts/benchmark_isolated_worker.py "$worker_image"
```

The benchmark starts its own strict-audit broker and runs three warmups
followed by 25 sequential launches. It reports the Linux host, Docker and
Rust versions, and median and 95th-percentile times. The timer includes
the launcher, local approval consumption, container start and exit, and
both synced audit records. Image pulls and approval issuance happen
outside the timed window.

## License and attribution

Spoor's original code is licensed under the [Apache License 2.0](LICENSE).
Selected detection rules were adapted from ThreatDefence and retain the
[ThreatDefence MIT notice](detections/LICENSE-THREATDEFENCE).
[ThreatDefence reference snapshot](https://github.com/ThreatDefence/agentic-attack-detections/tree/7a29e1683b0b2100baf4b1986870c12e7ffe4a2a)
