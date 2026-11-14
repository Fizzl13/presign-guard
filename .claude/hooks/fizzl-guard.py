#!/usr/bin/env python3
"""Fizzl guard: a PreToolUse hook that enforces Frits's standing rules in the tool path itself, so they don't depend
on the model remembering them (the same idea as x402-safe-fetch: the check sits in the payment path, not in the model).

It reads the hook's JSON on stdin and answers with a permission decision:
  deny  never allowed, whatever was said in the chat (wallet and agent keys, paying tools, Render and Railway writes,
        Sentry issue changes);
  ask   allowed only after Frits approves the prompt himself (the paying workflows index-payment, spot-buy and
        buy-check, npm publish, paid Higgsfield generation);
  (no output) everything else goes on as usual.

Rules from fizzl-brain (CLAUDE.md, rules.md). Tested by .claude/hooks/test_fizzl_guard.py.
"""
import json
import re
import sys

# Secret names whose values must never be read or used in a session. Matched only where a command would use the
# value ($NAME, ${NAME}, printenv NAME, process.env.NAME, os.environ...NAME), so a grep for the name in docs still runs.
SECRET_NAMES = [
    "BUY_WALLET_KEY", "SPOT_BUY_KEY", "XLAYER_DEPLOY_KEY", "CONCORDIUM_ANCHOR_KEY", "CONCORDIUM_ANCHOR_ACCOUNT",
    "WATCH_OWNER_KEY", "EXAM_SIGNING_KEY", "AGENT_PRIVATE_KEY", "OPERATOR_PRIVATE_KEY", "PASS_SALE_KEY", "DRAFT_KEY",
    "USAGE_LOG_SALT", "TELEGRAM_BOT_TOKEN",
]
_names = "|".join(SECRET_NAMES)
SECRET_USE = re.compile(
    rf"(\$\{{?({_names})\b|printenv\s+({_names})\b|process\.env(\.|\[['\"])({_names})\b|os\.(environ|getenv)\W+({_names})\b|\benv\s*\|\s*grep\s+[-\w\s]*({_names})\b)"
)
# A Fizzl Agent Wallet agent key pasted into a command.
AGENT_KEY = re.compile(r"\bawk_[A-Za-z0-9_-]{16,}")

# Workflows that spend real money from the spot-buy wallet: only on Frits's word ("Index", "Doe testkopen").
PAYING_WORKFLOW = re.compile(r"\b(index-payment|spot-buy|buy-check)\.ya?ml\b")
DISPATCH = re.compile(r"(/dispatches\b|workflow\s+run\b|run_workflow)")
NPM_PUBLISH = re.compile(r"\bnpm\s+publish\b")

# MCP tools.
RENDER_READ = re.compile(r"^mcp__Render__(list_|get_)")
COINBASE_READ = re.compile(
    r"^mcp__Coinbase__coinbase_(balance|fees|products_|orders_(get|list|fills|preview|edit_preview)|portfolios_(get|list)"
    r"|settlements_list|convert_(get|quote)|x402_resources|feedback_submit)"
)
# Railway: reading status, logs, metrics, deploys and docs is fine; anything that deploys, changes, creates or deletes
# is Frits's. Variables and bucket credentials can carry secret values, so they are not read either.
RAILWAY_READ = re.compile(
    r"^mcp__Railway__(whoami|list-(projects|services|deployments|domains|workspaces|webhooks|feature-flags|tcp-proxies|traces"
    r"|beta-features|cloud-agent-models|cloud-agent-tasks)|get-(status|logs|staged-changes|service-config|service-metrics"
    r"|deployment-diagnosis|trace|tracing|tracing-coverage|feature-flag|function-source-code|cloud-agent-transcript)"
    r"|describe-(environment|service|template)|environment-status|domain-status|http-(error-rate|requests|response-time)"
    r"|search-(docs|templates)|fetch-docs|check-cloud-agent-task)$"
)
# Railway set-up steps Frits may approve one by one (14 Nov 2026: "Doe jij het klikwerk maar"): a project, a service,
# its source, settings and domain, and deploying it. Variables, credentials and deleting stay his.
RAILWAY_SETUP = re.compile(
    r"^mcp__Railway__(create-project|create-service|create-deployment|connect-service-source|update-service|generate-domain"
    r"|accept-deploy|redeploy|restart-service)$"
)
SENTRY_CHANGE = re.compile(r"^mcp__Sentry__(update_|delete_|link_issue|unlink_issue|add_issue_note)")
SENTRY_CREATE = re.compile(r"^mcp__Sentry__create_")
PAYING_TOOL = re.compile(r"(pay_x402|x402_pay|x402_buy|safe_buy|paypal_.*pay|coinbase_transfer)", re.I)
HIGGSFIELD_READ = re.compile(
    r"^mcp__Higgsfield__(get_|list_|show_|models_explore|balance|jobs_wait|transactions|job_display|search_|"
    r"apps_search|apps_describe|gpu_list_|gpu_explore|gpu_my|gpu_job_quote|gpu_job_status|gpu_rental_logs|"
    r"ads_studio_(get_|list_|quote|story_presets|story_recipe)|video_analysis_(jobs|status)|website_status|"
    r"scene_builder_3d_(get_|list_|query_python|search_assets|show_scene))"
)


def decide(tool, inp):
    """Return (decision, reason) or None."""
    if tool == "Bash":
        cmd = str(inp.get("command", ""))
        if SECRET_USE.search(cmd):
            return "deny", "Fizzl rule: wallet, agent and service keys are never read or used in a session (Frits sets them himself)."
        if AGENT_KEY.search(cmd):
            return "deny", "Fizzl rule: an agent key (awk_...) is never pasted or used in a session."
        if PAYING_WORKFLOW.search(cmd) and DISPATCH.search(cmd):
            return "ask", "This starts a workflow that pays real money (index-payment, spot-buy or buy-check). Only on Frits's own word: approve only if he asked for it now."
        if NPM_PUBLISH.search(cmd):
            return "ask", "npm publish only on Frits's 'Publiceer'."
        return None

    if not tool.startswith("mcp__"):
        return None
    if PAYING_TOOL.search(tool):
        return "deny", "Fizzl rule: Claude never pays. This tool pays or moves money."
    if tool.startswith("mcp__Render__") and not RENDER_READ.match(tool):
        return "deny", "Fizzl rule: Render is read-only for Claude (no env changes, deploys or new services). Frits does those himself."
    if RAILWAY_SETUP.match(tool):
        return "ask", "Railway set-up step (project, service, source, settings, domain or deploy): only when Frits approves this one."
    if tool.startswith("mcp__Railway__") and not RAILWAY_READ.match(tool):
        return "deny", "Fizzl rule: Railway is read-only for Claude (no deploys, variables, new or deleted services). Frits does those himself."
    if tool.startswith("mcp__Coinbase__") and not COINBASE_READ.match(tool):
        return "deny", "Fizzl rule: never trade, transfer or pay with the Coinbase tools."
    if SENTRY_CHANGE.match(tool):
        return "deny", "Fizzl rule: never resolve or change Sentry issues."
    if SENTRY_CREATE.match(tool):
        return "ask", "Creating something in Sentry: only when Frits asked for it."
    if tool == "mcp__github__actions_run_trigger":
        if inp.get("method") == "run_workflow" and PAYING_WORKFLOW.search(str(inp.get("workflow_id", ""))):
            return "ask", "This starts a workflow that pays real money (index-payment, spot-buy or buy-check). Only on Frits's own word: approve only if he asked for it now."
        return None
    if tool.startswith("mcp__Higgsfield__") and not HIGGSFIELD_READ.match(tool):
        return "ask", "Higgsfield generation costs credits: only after a cost estimate and Frits's yes."
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    out = decide(str(data.get("tool_name", "")), data.get("tool_input") or {})
    if out:
        decision, reason = out
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
