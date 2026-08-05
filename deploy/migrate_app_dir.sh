#!/usr/bin/env bash
# One-time migration: /opt/email_summary -> /opt/letterlock.
#
# A move, not a copy: .env, .gmail-mcp/, node_modules/ and the venv (including
# the spaCy model, which is a ~600MB reinstall) all travel with the directory.
# The loose runtime files then go into state/, matching paths.RUN_DIR.
#
# The one thing a move breaks is the venv: a virtualenv writes its own absolute
# path into every console script's shebang and into pyvenv.cfg, so venv/bin/pip
# stops working while venv/bin/python (a symlink to the system python) keeps
# working. Those paths get rewritten below, and deploy.sh invokes pip as
# `python -m pip` so it does not depend on the shebang at all.
#
# Rollback: systemctl stop the units, mv the directory back, restore the unit
# files from the backup this script leaves in /root/.
#
#   DRY_RUN=1 ./deploy/migrate_app_dir.sh   # print the plan
#   ./deploy/migrate_app_dir.sh             # do it
#   ./deploy/deploy.sh                      # then deploy the code
set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/hezner}"
REMOTE="root@hezner.morganrivers.com"
OLD_DIR="${OLD_DIR:-/opt/email_summary}"
NEW_DIR="${NEW_DIR:-/opt/letterlock}"
LEGACY_CONFIG="/root/.system_files"

read -r -d '' SCRIPT <<REMOTE_SCRIPT || true
set -euo pipefail

if [ ! -d "$OLD_DIR" ]; then
    echo "no $OLD_DIR to migrate from" >&2
    exit 1
fi
if [ -e "$NEW_DIR" ]; then
    echo "$NEW_DIR already exists; refusing to overwrite" >&2
    exit 1
fi

BACKUP="/root/systemd-backup-\$(date +%Y%m%d-%H%M%S)"
echo "== backing up the installed unit files to \$BACKUP (the deploy overwrites them)"
mkdir -p "\$BACKUP"
cp -a /etc/systemd/system/email-*.service /etc/systemd/system/email-*.timer \\
      /etc/systemd/system/gmail-watch.* "\$BACKUP/"

echo "== stopping services so nothing is writing during the move"
systemctl stop email-daemon email-webhook || true

echo "== moving $OLD_DIR -> $NEW_DIR"
mv "$OLD_DIR" "$NEW_DIR"

echo "== grouping runtime files under state/"
mkdir -p "$NEW_DIR/state" "$NEW_DIR/config" "$NEW_DIR/database"
for f in state.json wake_queue.jsonl wake_queue.lock restart.flag; do
    if [ -f "$NEW_DIR/\$f" ]; then
        mv "$NEW_DIR/\$f" "$NEW_DIR/state/\$f"
    fi
done
# The FIFO is recreated by daemon_loop.ensure_fifo() in its new home.
rm -f "$NEW_DIR/wake.fifo"

echo "== copying operator prompts into config/"
for f in prompt_for_email voice-dna-email.md; do
    if [ -f "$LEGACY_CONFIG/\$f" ]; then
        cp -a "$LEGACY_CONFIG/\$f" "$NEW_DIR/config/\$f"
    else
        echo "   (missing $LEGACY_CONFIG/\$f)"
    fi
done

echo "== rewriting the venv's baked-in paths"
# -type f skips the python symlinks, which point at the system interpreter and
# must not be followed by sed.
find "$NEW_DIR/venv/bin" -maxdepth 1 -type f -exec \\
    sed -i "s|$OLD_DIR/venv|$NEW_DIR/venv|g" {} +
sed -i "s|$OLD_DIR/venv|$NEW_DIR/venv|g" "$NEW_DIR/venv/pyvenv.cfg"

echo "== verifying the venv"
"$NEW_DIR/venv/bin/python" -m pip --version
"$NEW_DIR/venv/bin/python" -c "import spacy; spacy.load('en_core_web_lg'); print('spacy model ok')"

echo "== done. Services are stopped; ./deploy/deploy.sh installs the new units and starts them."
REMOTE_SCRIPT

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[DRY RUN] would run on $REMOTE:"
    echo "$SCRIPT"
    exit 0
fi

ssh -i "$SSH_KEY" "$REMOTE" "bash -s" <<< "$SCRIPT"
