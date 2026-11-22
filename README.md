# Spoor

**Follow an ARTEX tool call from policy decision to audit evidence.**

An ARTEX worker asks to run a tool. Spoor can show what it requested, whether
policy allowed it, and what the tool reported afterward. It's an experimental
Rust broker and audit bridge for calls instrumented in a controlled lab.

Microsoft and the FBI documented ARTEX use in real intrusions in November 2026.
Spoor gives defenders a small, reproducible way to study the tool-call evidence
an instrumented agent can leave. [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/) · [FBI advisory](https://www.ic3.gov/CSA/2026/261113.pdf)

[Try a synthetic trace](#try-a-synthetic-trace) ·
[Explore the detections](#detection-rules) ·
[See what has been verified](#verification)

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
and Spoor carries the original session and parent command into the report. On
Linux the shim samples the parent command and redacts common credential patterns.

## Try a synthetic trace

Start here with a stable Rust toolchain and Cargo. The example reads two
synthetic records and writes a local preview. It needs neither ARTEX nor an
Agentmetry account.

<details>
<summary>PowerShell</summary>

```powershell
$demo = Join-Path (Get-Location) ".spoor-demo"
New-Item -ItemType Directory -Force -Path $demo | Out-Null
Copy-Item -LiteralPath examples/synthetic-events.jsonl -Destination (Join-Path $demo "broker-events.jsonl")
$env:BROKER_DATA_DIR = $demo
$env:SPOOR_STATE_DIR = $demo
$env:SPOOR_SOURCE = "broker"
cargo run --locked --manifest-path rust/Cargo.toml --bin spoor -- watch --once --dry-run
Get-Content (Join-Path $demo "ingest-preview.rust.jsonl") -Tail 2
```

</details>

<details>
<summary>Bash</summary>

```sh
mkdir -p .spoor-demo
cp examples/synthetic-events.jsonl .spoor-demo/broker-events.jsonl
BROKER_DATA_DIR=.spoor-demo SPOOR_STATE_DIR=.spoor-demo SPOOR_SOURCE=broker \
  cargo run --locked --manifest-path rust/Cargo.toml --bin spoor -- watch --once --dry-run
tail -n 2 .spoor-demo/ingest-preview.rust.jsonl
```

</details>

### Read the two events together

```mermaid
sequenceDiagram
    participant Trail as Synthetic broker trail
    participant Watcher as Spoor watcher
    participant Preview as Local audit preview
    Trail->>Watcher: Policy allows echo
    Watcher->>Preview: tool_called in demo-session
    Trail->>Watcher: Tool reports exit code 1
    Watcher->>Preview: tool_failed in demo-session
    Note over Watcher,Preview: Both events keep the same redacted parent command
```

`tool_called` tells you the broker allowed the request. `tool_failed` tells you
the command exited with an error. Both events have `demo-session` and carry
`synthetic-parent --token=[REDACTED]` in `tool.arguments.parent_command_line`.

## Detection rules

- [Sigma](detections/sigma) covers brokered tool activity with ARTEX or shell
  parent metadata, plus web log signals such as ARTEX user agents.
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
| `examples` | Synthetic broker trail used in the quick start |

## Verification

The source lab passed 42 Rust tests with one ignored benchmark and 77 replay
cases. A separate loopback check used the real broker and watcher with a mock
Agentmetry endpoint and verified session and parent metadata on both decision
and failure events. Live Agentmetry storage of the new field is still unverified.

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

The broker is designed for a trusted loopback boundary. Use operating system
and network controls for isolation. The example policy permits unmatched
commands, so review it for your environment. Parent command capture is optional
and redaction is best effort. Treat audit trails as sensitive and restrict
access to them.

## License and attribution

Spoor's original code is licensed under the [Apache License 2.0](LICENSE).
Selected detection rules were adapted from ThreatDefence and retain the
[ThreatDefence MIT notice](detections/LICENSE-THREATDEFENCE).
[ThreatDefence reference snapshot](https://github.com/ThreatDefence/agentic-attack-detections/tree/7a29e1683b0b2100baf4b1986870c12e7ffe4a2a)
