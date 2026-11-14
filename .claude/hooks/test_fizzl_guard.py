#!/usr/bin/env python3
"""Tests for fizzl-guard.py: run `python3 .claude/hooks/test_fizzl_guard.py`."""
import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fizzl-guard.py")


def run(tool, inp):
    out = subprocess.run([sys.executable, "-I", HOOK], input=json.dumps({"tool_name": tool, "tool_input": inp}), capture_output=True, text=True, check=True).stdout.strip()
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else None


CASES = [
    # Keys: using the value is denied, mentioning the name is fine.
    ("Bash", {"command": "echo $SPOT_BUY_KEY"}, "deny"),
    ("Bash", {"command": "node pay.js --key ${BUY_WALLET_KEY}"}, "deny"),
    ("Bash", {"command": "printenv CONCORDIUM_ANCHOR_KEY"}, "deny"),
    ("Bash", {"command": "node -e 'console.log(process.env.WATCH_OWNER_KEY)'"}, "deny"),
    ("Bash", {"command": "python3 -c 'import os; print(os.environ[\"XLAYER_DEPLOY_KEY\"])'"}, "deny"),
    ("Bash", {"command": "env | grep EXAM_SIGNING_KEY"}, "deny"),
    ("Bash", {"command": "grep -rn BUY_WALLET_KEY docs/"}, None),
    ("Bash", {"command": "curl -H 'authorization: Bearer awk_live_4f9a8b7c6d5e4f3a2b1c' https://wallet.fizzl.eu/v1/pay"}, "deny"),
    # Paying workflows ask; others run.
    ("Bash", {"command": "gh api -X POST repos/Fizzl13/x402-doctor/actions/workflows/index-payment.yml/dispatches --input p.json"}, "ask"),
    ("Bash", {"command": "gh workflow run spot-buy.yml -R Fizzl13/x402-doctor"}, "ask"),
    ("Bash", {"command": "gh api repos/Fizzl13/x402-doctor/actions/workflows/spot-buy.yml/runs"}, None),
    ("Bash", {"command": "gh api -X POST repos/Fizzl13/concordium-next/actions/workflows/trust-anchor.yml/dispatches -f ref=main"}, None),
    ("Bash", {"command": "gh api -X POST repos/Fizzl13/x402-examples/actions/workflows/outreach-draft.yml/dispatches --input p.json"}, None),
    ("Bash", {"command": "cd safe-fetch && npm publish --access public"}, "ask"),
    ("Bash", {"command": "npm test"}, None),
    # MCP.
    ("mcp__Render__list_logs", {}, None),
    ("mcp__Render__get_metrics", {}, None),
    ("mcp__Render__update_environment_variables", {}, "deny"),
    ("mcp__Render__trigger_deploy", {}, "deny"),
    ("mcp__Render__create_web_service", {}, "deny"),
    ("mcp__Coinbase__coinbase_balance", {}, None),
    ("mcp__Coinbase__coinbase_orders_create", {}, "deny"),
    ("mcp__Coinbase__coinbase_x402_pay", {}, "deny"),
    ("mcp__Coinbase__coinbase_transfer", {}, "deny"),
    ("mcp__AgentFuel__safe_buy", {}, "deny"),
    ("mcp__AgentFuel__rugcheck", {}, None),
    ("mcp__fizzl-wallet__pay_x402", {}, "deny"),
    ("mcp__Sentry__search_issues", {}, None),
    ("mcp__Sentry__update_issue", {}, "deny"),
    ("mcp__Sentry__create_uptime_monitor", {}, "ask"),
    ("mcp__github__actions_run_trigger", {"method": "run_workflow", "workflow_id": "index-payment.yml"}, "ask"),
    ("mcp__github__actions_run_trigger", {"method": "run_workflow", "workflow_id": "outreach-draft.yml"}, None),
    ("mcp__github__actions_run_trigger", {"method": "rerun_failed_jobs", "run_id": 1}, None),
    ("mcp__Higgsfield__balance", {}, None),
    ("mcp__Higgsfield__generate_video", {}, "ask"),
    ("mcp__x402_Doctor__x402_quick_check", {}, None),
    ("Read", {"file_path": "/etc/hosts"}, None),
]


def main():
    bad = 0
    for tool, inp, want in CASES:
        got = run(tool, inp)
        if got != want:
            bad += 1
            print(f"FAIL {tool} {inp}: want {want}, got {got}")
    print(f"{len(CASES) - bad}/{len(CASES)} ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
