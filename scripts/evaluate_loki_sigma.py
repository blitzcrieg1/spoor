"""Convert Spoor's Sigma process rule and run its fixtures against test Loki."""

import argparse
import json
import re
import secrets
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.loki import LokiCustomAttributes, SetCustomAttributeTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations.base import ValueTransformation
from sigma.types import SigmaRegularExpression

from evaluate_lab_sigma import FIXTURE_PATH, RULE_PATH


class LokiRegexSearch(ValueTransformation):
    def apply_value(
        self, field: str | None, value: SigmaRegularExpression,
    ) -> SigmaRegularExpression:
        # Loki's label regexes match the entire field. Keep Sigma's search
        # behavior and leave any anchors inside the original expression.
        pattern = value.to_plain()
        leading_flags = re.match(r"^\(\?[ims]+\)", pattern)
        prefix = leading_flags[0] if leading_flags else ""
        pattern = pattern[len(prefix):]
        return SigmaRegularExpression(
            f"{prefix}(?s:.*)(?:{pattern})(?s:.*)", flags=set(value.flags), policy=value.policy,
        )


def convert(selector):
    pipeline = ProcessingPipeline(items=[
        ProcessingItem(SetCustomAttributeTransformation(
            attribute=LokiCustomAttributes.LOGSOURCE_SELECTION.value, value=selector,
        )),
        ProcessingItem(SetCustomAttributeTransformation(
            attribute=LokiCustomAttributes.PARSER.value, value="json",
        )),
        ProcessingItem(LokiRegexSearch()),
    ])
    rule = SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8"))
    query, = LogQLBackend(pipeline).convert(rule)
    return query


def wait_until_ready(base):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            with urlopen(base + "/ready", timeout=2):
                return
        except (URLError, TimeoutError):
            time.sleep(0.5)
    raise SystemExit("Loki did not become ready within 45 seconds.")


def query_ids(base, query, start, end, limit):
    params = urlencode({"query": query, "start": start, "end": end, "limit": limit})
    with urlopen(f"{base}/loki/api/v1/query_range?{params}", timeout=10) as response:
        result = json.load(response)
    if result["status"] != "success" or result["data"]["resultType"] != "streams":
        raise SystemExit("Loki did not return a successful log query result.")
    return {
        json.loads(line)["spoor_fixture_id"]
        for stream in result["data"]["result"]
        for _, line in stream["values"]
    }


def check(base, fixtures):
    ids = set(range(len(fixtures)))
    if not ids:
        raise SystemExit("No Sigma fixtures were loaded.")
    run = secrets.token_hex(8)
    labels = {"job": "spoor-sigma-test", "fixture_run": run}
    selector = f'{{job="spoor-sigma-test",fixture_run="{run}"}}'
    query = convert(selector)
    wait_until_ready(base)

    start = time.time_ns() - 1_000_000_000
    values = [
        [str(start + index), json.dumps(dict(fixture["event"], spoor_fixture_id=index))]
        for index, fixture in enumerate(fixtures)
    ]
    request = Request(
        base + "/loki/api/v1/push",
        data=json.dumps({"streams": [{"stream": labels, "values": values}]}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=10):
        pass

    end = start + len(fixtures)
    if query_ids(base, selector, start, end, len(fixtures)) != ids:
        raise SystemExit("Loki did not return every fixture in the control query.")
    matched = query_ids(base, query, start, end, len(fixtures))
    print(query)

    correct = True
    for index, fixture in enumerate(fixtures):
        actual = index in matched
        passed = fixture["expected"] == actual
        correct = correct and passed
        result = "PASS" if passed else "FAIL"
        print(f"{result} {fixture['name']}: expected={fixture['expected']} matched={actual}")
    if not correct:
        raise SystemExit(1)
    print(f"Loki Sigma fixtures passed: {len(matched)} matches, {len(fixtures) - len(matched)} exclusions.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loki-url", default="http://127.0.0.1:3100", help="Disposable Loki endpoint")
    parser.add_argument("--print-query", action="store_true", help='Print LogQL for the job="spoor" stream')
    parser.add_argument("--agentmetry", action="store_true", help="Use events exported by Agentmetry v0.13.0")
    args = parser.parse_args()
    if args.print_query:
        print(convert('{job="spoor"}'))
        return
    if args.agentmetry:
        from agentmetry_sigma_fixtures import export_fixtures

        fixtures = export_fixtures()
    else:
        fixtures = [
            json.loads(line)
            for line in FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    try:
        check(args.loki_url.rstrip("/"), fixtures)
    except HTTPError as error:
        detail = error.read(1000).decode("utf-8", errors="replace").strip()
        raise SystemExit(f"Loki HTTP {error.code}: {detail}") from error


if __name__ == "__main__":
    main()
