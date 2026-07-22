#!/usr/bin/env bash
set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/hezner}"
REMOTE_USER="root"
REMOTE_HOST="hezner.morganrivers.com"
REMOTE_DIR="/opt/email_summary"
SYSTEMD_DIR="/etc/systemd/system"
SERVICES=(email-daemon email-webhook billing-webhook onboarding)

PROMPT_LOCAL="$HOME/.system_files/prompt_for_email"
PROMPT_REMOTE="/root/.system_files/prompt_for_email"

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

RSYNC_FLAGS=(-avz --itemize-changes)
if [ "${DRY_RUN:-0}" = "1" ]; then
    RSYNC_FLAGS+=(--dry-run)
    echo "[DRY RUN] no changes will be pushed"
fi

EXCLUDES=(
    --exclude='.git/'
    --exclude='.gitignore'
    --exclude='__pycache__/'
    --exclude='node_modules/'
    --exclude='venv/'
    --exclude='.gmail-mcp/'
    --exclude='*.bak'
    --exclude='*.bak[0-9]*'
    --exclude='test_*.py'
    --exclude='.env'
    --exclude='.env.*'
    --exclude='deploy.sh'
    --exclude='CLAUDE.md'
    --exclude='state.json'
    --exclude='database/'
    --exclude='tests/'
    --exclude='docs/'
    --exclude='frontend/'
    --exclude='wake.fifo'
    --exclude='wake_queue.jsonl'
    --exclude='wake_queue.lock'
    --exclude='restart.flag'
    --exclude='push.log'
)

echo "==> Syncing repo: $REPO_DIR -> $REMOTE_HOST:$REMOTE_DIR"
rsync "${RSYNC_FLAGS[@]}" "${EXCLUDES[@]}" \
    -e "ssh -i $SSH_KEY" \
    "$REPO_DIR/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

echo "==> Syncing systemd units: deploy/hetzner -> $REMOTE_HOST:$SYSTEMD_DIR"
rsync "${RSYNC_FLAGS[@]}" \
    -e "ssh -i $SSH_KEY" \
    "$REPO_DIR/deploy/hetzner/"*.service "$REPO_DIR/deploy/hetzner/"*.timer \
    "$REMOTE_USER@$REMOTE_HOST:$SYSTEMD_DIR/"

if [ -f "$PROMPT_LOCAL" ]; then
    echo "==> Syncing prompt: $PROMPT_LOCAL -> $REMOTE_HOST:$PROMPT_REMOTE"
    rsync "${RSYNC_FLAGS[@]}" \
        -e "ssh -i $SSH_KEY" \
        "$PROMPT_LOCAL" "$REMOTE_USER@$REMOTE_HOST:$PROMPT_REMOTE"
else
    echo "==> Skipping prompt (not found at $PROMPT_LOCAL)"
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[DRY RUN] not reloading systemd or restarting services"
else
    echo "==> Reloading systemd and restarting: ${SERVICES[*]}"
    ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" \
        "systemctl daemon-reload && systemctl restart ${SERVICES[*]}"
fi

echo "==> Done"
