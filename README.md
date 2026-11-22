# Spoor

Spoor is an experimental Rust policy broker and audit bridge for agent tool
calls. It evaluates a requested command against a local policy, records the
decision and report as JSONL, and maps those records to Agentmetry audit events
or TraceSig exports. The included detection rules cover selected agent
behaviors in logs and network telemetry.

## What it records

1. The broker answers `/decide` with `allow`, `deny`, or `ask` and a call ID.
2. The shim requests a decision before running a permitted local tool and
   submits its exit code to `/report`. On Linux it can attach a bounded parent
   command with common credential patterns redacted.
3. Spoor retains the decision's session and parent metadata on the corresponding
   report. The watcher maps that metadata to
   `tool.arguments.parent_command_line`.

## Quick start

Install a current stable Rust toolchain with Cargo. From the repository root,
build the workspace.

```sh
cargo build --locked --manifest-path rust/Cargo.toml --workspace
```

Run the watcher against the included synthetic trail in dry-run mode. This
demonstrates the payload without credentials or a collector.

**PowerShell**

```powershell
$demo = Join-Path (Get-Location) ".spoor-demo"
New-Item -ItemType Directory -Force -Path $demo | Out-Null
Copy-Item examples/synthetic-events.jsonl (Join-Path $demo "broker-events.jsonl")
$env:BROKER_DATA_DIR = $demo
$env:SPOOR_STATE_DIR = $demo
$env:SPOOR_SOURCE = "broker"
cargo run --locked --manifest-path rust/Cargo.toml --bin spoor -- watch --once --dry-run
Get-Content (Join-Path $demo "ingest-preview.rust.jsonl")
```

**Bash**

```sh
mkdir -p .spoor-demo
cp examples/synthetic-events.jsonl .spoor-demo/broker-events.jsonl
BROKER_DATA_DIR=.spoor-demo SPOOR_STATE_DIR=.spoor-demo SPOOR_SOURCE=broker \
  cargo run --locked --manifest-path rust/Cargo.toml --bin spoor -- watch --once --dry-run
cat .spoor-demo/ingest-preview.rust.jsonl
```

The preview contains a `tool_called` event and a `tool_failed` event with the
same session and `synthetic-parent --token=[REDACTED]` as the parent command.
The watcher appends preview rows on each run.

## Repository layout

| Path | Contents |
| --- | --- |
| `rust/spoor` | Broker, audit watcher, model request proxy, and TraceSig exporter |
| `rust/spoor-core` | Policy, event mapping, deduplication, and signal matching |
| `rust/spoor-shim` | Tool mediation and Linux parent command capture |
| `rust/policy.json` | Example policy from the local lab |
| `detections` | Experimental Sigma, Suricata, and TraceSig rules |
| `examples` | Synthetic broker trail used in the quick start |

## Verification

The source lab passed 42 Rust tests with one ignored benchmark and 77 replay
cases. A separate loopback check used the real broker and watcher with a mock
Agentmetry endpoint and verified session and parent metadata on both decision
and failure events. Live Agentmetry storage of the new field is still unverified.

Run the included Rust tests with:

```sh
cargo test --locked --manifest-path rust/Cargo.toml --workspace
```

The focused process rule fixture check uses Python and PyYAML.

```sh
python scripts/evaluate_lab_sigma.py
```

## Deployment limits

The broker is designed for a trusted loopback boundary. Use operating system
and network controls for isolation. The example policy permits unmatched
commands, so review it for your environment. Parent command capture is optional
and redaction is best effort. Treat audit trails as sensitive and restrict
access to them. Detection matches are triage leads.

## License and attribution

Spoor's original code is licensed under the [Apache License 2.0](LICENSE).
Selected detection rules were adapted from ThreatDefence and retain the
[ThreatDefence MIT notice](detections/LICENSE-THREATDEFENCE).
[ThreatDefence reference snapshot](https://github.com/ThreatDefence/agentic-attack-detections/tree/7a29e1683b0b2100baf4b1986870c12e7ffe4a2a)
