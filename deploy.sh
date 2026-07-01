#!/usr/bin/env bash
set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/dmrweb}"
REMOTE_USER="morganrivers_morganrivers"
REMOTE_HOST="ssh.nyc1.nearlyfreespeech.net"
REMOTE_DIR="/home/protected/email_summary"

PROMPT_LOCAL="$HOME/.system_files/prompt_for_email"
PROMPT_REMOTE="/home/private/.system_files/prompt_for_email"

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
    --exclude='*.bak'
    --exclude='*.bak[0-9]*'
    --exclude='test_*.py'
    --exclude='.env'
    --exclude='.env.*'
    --exclude='deploy.sh'
    --exclude='CLAUDE.md'
    --exclude='state.json'
    --exclude='wake.fifo'
    --exclude='restart.flag'
    --exclude='process_push.lock'
    --exclude='push.log'
)

echo "==> Syncing repo: $REPO_DIR -> $REMOTE_HOST:$REMOTE_DIR"
rsync "${RSYNC_FLAGS[@]}" "${EXCLUDES[@]}" \
    -e "ssh -i $SSH_KEY" \
    "$REPO_DIR/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

if [ -f "$PROMPT_LOCAL" ]; then
    echo "==> Syncing prompt: $PROMPT_LOCAL -> $REMOTE_HOST:$PROMPT_REMOTE"
    rsync "${RSYNC_FLAGS[@]}" \
        -e "ssh -i $SSH_KEY" \
        "$PROMPT_LOCAL" "$REMOTE_USER@$REMOTE_HOST:$PROMPT_REMOTE"
else
    echo "==> Skipping prompt (not found at $PROMPT_LOCAL)"
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[DRY RUN] not arming restart.flag"
else
    echo "==> Arming daemon restart"
    ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "touch $REMOTE_DIR/restart.flag"
fi

echo "==> Done"
