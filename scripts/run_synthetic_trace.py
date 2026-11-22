"""Run the README's synthetic broker trail through the Spoor watcher."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SESSION = "demo-session"
PARENT = "synthetic-parent --token=[REDACTED]"


def main() -> None:
    demo_dir = ROOT / ".spoor-demo"
    demo_dir.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(dir=demo_dir) as folder:
        data_dir = Path(folder)
        shutil.copyfile(ROOT / "examples" / "synthetic-events.jsonl",
                        data_dir / "broker-events.jsonl")
        env = dict(os.environ, BROKER_DATA_DIR=folder, SPOOR_STATE_DIR=folder,
                   SPOOR_SOURCE="broker")
        subprocess.run(
            ["cargo", "run", "--locked", "--manifest-path", "rust/Cargo.toml",
             "--bin", "spoor", "--", "watch", "--once", "--dry-run"],
            cwd=ROOT, env=env, check=True,
        )

        preview = data_dir / "ingest-preview.rust.jsonl"
        lines = preview.read_text(encoding="utf-8").splitlines()
        events = [json.loads(line) for line in lines]
        if [event["event_type"] for event in events] != ["tool_called", "tool_failed"]:
            raise SystemExit("Expected exactly one decision event and one failure event.")
        for event, outcome in zip(events, ("success", "error")):
            if (
                event["session_id"] != SESSION
                or event["correlation_id"] != SESSION
                or event["tool"]["arguments"]["parent_command_line"] != PARENT
                or event["outcome"] != outcome
            ):
                raise SystemExit("The preview lost the session, redacted parent, or outcome.")
        if {path.name for path in data_dir.iterdir()} != {
            "broker-events.jsonl", "ingest-preview.rust.jsonl",
        }:
            raise SystemExit("Dry run wrote files beyond the expected trail and preview.")

        print("\n".join(lines))
        print("Verified both events share the session, correlation ID, and redacted parent.")


if __name__ == "__main__":
    main()
