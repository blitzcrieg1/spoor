# Pair Spoor calls in Agentmetry

This example forwards [two synthetic calls](../examples/synthetic-events.jsonl)
to a disposable local Agentmetry v0.13.0 instance. Both calls share one session.
One reports exit code 0 and the other reports exit code 7. Spoor reads the
fixture as audit data.

## Forward the sample trail

Use a local Agentmetry instance with external ingest and the file audit sink
enabled. Set `AGENTMETRY_URL` and, when required, `AGENTMETRY_API_KEY` in the
watcher's environment as described in the [integration guide](../README.md#forward-to-agentmetry).
Use a fresh instance or an empty audit data directory for this example. The
commands use Bash, stable Rust with Cargo, and Python 3.

From the Spoor repository root in Bash, copy the sample to a fresh watcher
directory and forward it.

```bash
trail_dir="$(mktemp -d)"
cp examples/synthetic-events.jsonl "$trail_dir/broker-events.jsonl"
BROKER_DATA_DIR="$trail_dir" SPOOR_STATE_DIR="$trail_dir" SPOOR_SOURCE=broker SPOOR_DRY_RUN=0 \
  cargo run --locked --manifest-path rust/Cargo.toml -p spoor -- watch --once --policy rust/policy.json
```

## Read decisions and completions

Replace the sample path below with `audit-forward.jsonl` in Agentmetry's data
directory. The example filters on `source.adapter` and `session_id`, then pairs
the records by `tool.arguments.call_id`. Counting one completion per call ID
gives the number of executions reported in this session, including failures.

```bash
python3 - /path/to/agentmetry/audit-forward.jsonl <<'PY'
import json
import sys

calls = {}
with open(sys.argv[1], encoding="utf-8") as trail:
    for line in trail:
        if not line.strip():
            continue
        row = json.loads(line)
        event = row.get("event", row)
        if (event.get("source") or {}).get("adapter") != "spoor":
            continue
        if event.get("session_id") != "demo-session":
            continue
        arguments = ((event.get("tool") or {}).get("arguments") or {})
        call_id, phase = arguments.get("call_id"), arguments.get("phase")
        if call_id and phase in ("authorization", "completion"):
            calls.setdefault(call_id, {})[phase] = event

print("call_id  authorization  completion  exit_code")
for call_id, phases in sorted(calls.items()):
    authorization = phases.get("authorization", {}).get("action", {}).get("outcome", "-")
    completion = phases.get("completion", {})
    outcome = completion.get("action", {}).get("outcome", "-")
    exit_code = completion.get("tool", {}).get("arguments", {}).get("exit_code", "-")
    print(call_id, authorization, outcome, exit_code, sep="  ")
print("Completed executions", sum("completion" in phases for phases in calls.values()))
PY
```

Expected output

```text
call_id  authorization  completion  exit_code
demo-1  pending  success  0
demo-2  pending  error  7
Completed executions 2
```

Agentmetry v0.13.0 can store both phases under `action.type=tool_called`.
Use `tool.arguments.phase=completion` when counting executions.
