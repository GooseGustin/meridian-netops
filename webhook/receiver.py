# webhook/receiver.py
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
import hmac
import hashlib
import subprocess
import json
import logging
import os
import httpx
from datetime import datetime
from collections import defaultdict
import time

app = FastAPI(title="Meridian Security Automation Webhook")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

WEBHOOK_SECRET = "meridian-change-in-production"
VAULT_PASS_FILE = "/tmp/.vault_pass"
INVENTORY = "inventory/hosts.yaml"
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Per-action rate limiter: max 5 per action:target per minute
_rate_tracker = defaultdict(list)
RATE_LIMIT = 5
RATE_WINDOW = 60  # seconds

# Per-target attack detector: max 10 total remediations per target per 5 minutes
_target_tracker = defaultdict(list)
ATTACK_THRESHOLD = 10
ATTACK_WINDOW = 300  # 5 minutes

ALLOWED_ACTIONS = {
    "block_host": "playbooks/block_host.yaml",
    "enforce_acl": "playbooks/remediate.yaml",
    "reset_vty": "playbooks/harden_vty.yaml",
}


def verify_signature(payload: bytes, signature: str) -> bool:
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def is_rate_limited(action: str, target: str) -> bool:
    """Per-action:target rate limit — max RATE_LIMIT per RATE_WINDOW seconds."""
    key = f"{action}:{target}"
    now = time.time()
    _rate_tracker[key] = [t for t in _rate_tracker[key] if now - t < RATE_WINDOW]
    if len(_rate_tracker[key]) >= RATE_LIMIT:
        return True
    _rate_tracker[key].append(now)
    return False


def is_under_attack(target: str) -> bool:
    """
    Per-target attack detection — if a target receives 10+ remediations
    (across ALL actions) within 5 minutes, flag it as potentially under
    attack and stop executing remediations for it.

    This prevents a compromised monitoring system from using the webhook
    receiver as a DoS tool against the network.
    """
    now = time.time()
    _target_tracker[target] = [
        t for t in _target_tracker[target] if now - t < ATTACK_WINDOW
    ]
    count = len(_target_tracker[target])
    if count >= ATTACK_THRESHOLD:
        return True
    # Record this attempt (not yet over threshold — still executing)
    _target_tracker[target].append(now)
    return False


def send_attack_alert(target: str, count: int):
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not set — skipping attack alert")
        return
    payload = {
        "text": f"🚨 *Attack pattern detected* — target `{target}` has received "
                f"{count}+ remediations in 5 minutes. Further remediations BLOCKED. "
                f"Investigate immediately.",
        "attachments": [{
            "color": "danger",
            "text": f"Time: {datetime.utcnow().isoformat()}Z\n"
                    f"Webhook receiver is NOT executing further remediations on {target} "
                    f"until the 5-minute window clears."
        }]
    }
    try:
        # Use sync httpx in a thread — this runs in a background task so blocking is fine
        import requests
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        logger.error(f"Failed to send attack alert: {e}")


def run_remediation(action: str, target: str, extra_vars: dict):
    playbook = ALLOWED_ACTIONS[action]
    extra = " ".join(f"-e {k}={v}" for k, v in extra_vars.items())
    cmd = [
        "ansible-playbook", playbook,
        "--inventory", INVENTORY,
        "--vault-password-file", VAULT_PASS_FILE,
        "-e", f"target_host={target}",
    ] + ([extra] if extra else [])

    logger.info(f"Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd="/home/goose/meridian-lab"
    )

    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "target": target,
        "rc": result.returncode,
        "stdout_tail": result.stdout[-300:],
    }
    with open("/tmp/remediation_audit.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return result.returncode == 0


@app.post("/webhook/security-event")
async def handle_event(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    signature = request.headers.get("X-Signature-256", "")

    if not verify_signature(body, signature):
        logger.warning("Invalid webhook signature rejected")
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = json.loads(body)
    action = event.get("action")
    target = event.get("target")
    extra_vars = event.get("extra_vars", {})

    if action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")

    # Check per-target attack threshold FIRST (more severe)
    if is_under_attack(target):
        count = len(_target_tracker[target])
        logger.warning(f"Attack pattern on {target}: {count} remediations in 5 min — BLOCKED")
        background_tasks.add_task(send_attack_alert, target, count)
        return {
            "status": "blocked",
            "reason": "attack_pattern_detected",
            "message": (
                f"{target} has exceeded {ATTACK_THRESHOLD} total remediations "
                f"in {ATTACK_WINDOW}s. Further actions blocked. Alert sent."
            )
        }

    # Check per-action rate limit
    if is_rate_limited(action, target):
        logger.warning(f"Rate limit exceeded: {action} on {target}")
        return {
            "status": "rate_limited",
            "message": f"Max {RATE_LIMIT} '{action}' remediations per {RATE_WINDOW}s exceeded for {target}"
        }

    background_tasks.add_task(run_remediation, action, target, extra_vars)
    return {"status": "accepted", "action": action, "target": target}


@app.get("/audit-log")
async def get_audit_log():
    try:
        with open("/tmp/remediation_audit.log") as f:
            entries = [json.loads(line) for line in f if line.strip()]
        return {"entries": entries[-50:]}
    except FileNotFoundError:
        return {"entries": []}


@app.get("/rate-status/{target}")
async def get_rate_status(target: str):
    """Diagnostic endpoint — shows current rate tracking for a target."""
    now = time.time()
    target_count = len([t for t in _target_tracker.get(target, [])
                        if now - t < ATTACK_WINDOW])
    per_action = {}
    for action in ALLOWED_ACTIONS:
        key = f"{action}:{target}"
        per_action[action] = len([t for t in _rate_tracker.get(key, [])
                                   if now - t < RATE_WINDOW])
    return {
        "target": target,
        "total_in_5min": target_count,
        "attack_threshold": ATTACK_THRESHOLD,
        "under_attack": target_count >= ATTACK_THRESHOLD,
        "per_action_in_60s": per_action,
    }
