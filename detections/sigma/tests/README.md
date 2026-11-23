# Verify the Spoor Sigma rule in Loki

The six [synthetic fixtures](fixtures/agent_shell_spawns_attack_tool.jsonl)
exercise the [Spoor process rule](../artex_agent_shell_spawns_attack_tool.yml).
The backend check parses the rule with pySigma, converts it to LogQL, uploads
the fixture records to a disposable Loki instance, and checks which records
Loki returns. A control query confirms that Loki ingested all six first.

| Sigma field | Parsed LogQL label |
| --- | --- |
| `tool.arguments.phase` | `tool_arguments_phase` |
| `tool.arguments.command` | `tool_arguments_command` |
| `tool.arguments.parent_command_line` | `tool_arguments_parent_command_line` |

Loki's `json` stage flattens nested fields using underscores. The input is
one Spoor event body per JSON line. Loki label regexes match the full field,
so the converter wraps the Sigma regexes to preserve substring matching.
It keeps the original anchors and boundaries inside the wrapped pattern.

## Reproduce the check

In one terminal, start a disposable Loki 3.7.10 instance on loopback.

```sh
docker run --rm -p 127.0.0.1:3100:3100 grafana/loki:3.7.10 \
  -config.file=/etc/loki/local-config.yaml -reporting.enabled=false
```

In another terminal, run these commands from the Spoor repository root.
Use Python 3.11 or newer in an environment dedicated to this check.

```sh
python -m pip install pySigma==2.1.1 pySigma-backend-loki==0.16.0
python scripts/evaluate_loki_sigma.py
```

Loki 3.7.10 returned both expected matches, a completion under an agent
parent and a failed completion under a shell parent. It excluded the benign
tool, unrelated parent, denied call, and authorization without completion.

To print the query for a stream labeled `job=spoor` without sending fixtures,
run `python scripts/evaluate_loki_sigma.py --print-query`. Set the stream
selector to match your own ingestion labels.
