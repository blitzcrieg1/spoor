"""Send synthetic broker records through Spoor and Agentmetry's file audit sink."""

import json
import os
from pathlib import Path
import tempfile

from check_isolated_worker import running_agentmetry
from run_synthetic_trace import TRAIL, binaries, forward_trace, require


SESSION = "spoor-sigma-export"
PARENT = "/app/artex --worker"
# These command fields are fixture text. No command from the trail is executed.
CALLS = {"matching-tool": "nmap", "benign-tool": "echo hello"}


def export_fixtures():
    spoor, _ = binaries()
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        recorder = directory / "agentmetry"
        with (directory / TRAIL).open("w", encoding="utf-8") as trail:
            for call_id, command in CALLS.items():
                record = {
                    "call_id": call_id, "session": SESSION, "tool": command.split()[0],
                    "command": command, "parent_command_line": PARENT,
                }
                trail.write(json.dumps(dict(record, type="decide", decision="allow")) + "\n")
                trail.write(json.dumps(dict(record, type="report", exit_code=0)) + "\n")
        with running_agentmetry(recorder) as (base, api_key):
            env = dict(
                os.environ, AGENTMETRY_URL=base, AGENTMETRY_API_KEY=api_key,
                BROKER_DATA_DIR=str(directory), SPOOR_STATE_DIR=str(directory),
                SPOOR_SOURCE="broker", SPOOR_DRY_RUN="0",
            )
            env.pop("AGENTMETRY_HOST_HEADER", None)
            forward_trace(spoor, env)
        saved = (recorder / "audit-forward.jsonl").read_text(encoding="utf-8")

    expected = {
        (call_id, phase): command
        for call_id, command in CALLS.items()
        for phase in ("authorization", "completion")
    }
    fixtures = []
    for line in saved.splitlines():
        row = json.loads(line)
        event = row.get("event", row)
        if event.get("session_id") != SESSION:
            continue
        arguments = event["tool"]["arguments"]
        call_id = arguments.get("call_id")
        phase = arguments.get("phase")
        command = expected.pop((call_id, phase), None)
        require(
            command is not None and arguments.get("command") == command
            and arguments.get("parent_command_line") == PARENT
            and event["source"]["adapter"] == "spoor",
            "Agentmetry export lost or changed the Spoor process fields or call pairing.",
        )
        fixtures.append({
            "name": f"Agentmetry export {call_id} {phase}",
            "expected": call_id == "matching-tool" and phase == "completion",
            "event": event,
        })
    require(not expected, "Agentmetry export did not contain both phases for each Spoor call.")
    print("Agentmetry export preserved phase, command, parent command line, and call ID for all four records.")
    return fixtures
