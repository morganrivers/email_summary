#!/usr/bin/env bash
set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/hezner}"
REMOTE_USER="root"
REMOTE_HOST="hezner.morganrivers.com"
REMOTE_DIR="/opt/letterlock"
SYSTEMD_DIR="/etc/systemd/system"
# We deploy over ssh as root, but nothing we deploy *runs* as root.
SERVICE_USER="letterlock"

# Operator-supplied prompts. Not in git: they live in the operator's home and
# are deployed into the app's config/, which is where paths.config_file() looks
# first. Named one by one because ~/.system_files holds unrelated files too.
CONFIG_LOCAL="$HOME/.system_files"
CONFIG_REMOTE="$REMOTE_DIR/config/"
CONFIG_FILES=(prompt_for_email voice-dna-email.md)

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_DIR="$REPO_DIR/deploy/hetzner"
[ -d "$REPO_DIR/backend" ] || { echo "REPO_DIR=$REPO_DIR is not the repo root (no backend/)" >&2; exit 1; }
[ -d "$UNIT_DIR" ] || { echo "REPO_DIR=$REPO_DIR has no deploy/hetzner" >&2; exit 1; }

DRY_RUN="${DRY_RUN:-0}"
remote() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "[DRY RUN] would run on $REMOTE_HOST: $*"
        return 0
    fi
    ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "$@"
}

RSYNC_FLAGS=(-avz --itemize-changes)
if [ "$DRY_RUN" = "1" ]; then
    RSYNC_FLAGS+=(--dry-run)
    echo "[DRY RUN] no changes will be pushed"
fi

# Everything not excluded here is owned by git: --delete-after removes remote
# files the repo no longer has, so a rename or a restructure leaves no stale
# copy behind for a stray import to pick up. rsync never deletes an excluded
# path, which makes this list the protected set. Runtime state is a directory
# (state/) rather than loose files beside the source, so the protected set is
# now whole directories plus the two secrets -- see CLAUDE.md.
EXCLUDES=(
    --exclude='.git/'
    --exclude='.gitignore'
    --exclude='__pycache__/'
    --exclude='.pytest_cache/'
    --exclude='.claude/'
    --exclude='masking_eval/'
    --exclude='*.bak'
    --exclude='*.bak[0-9]*'
    --exclude='deploy.sh'
    --exclude='CLAUDE.md'
    --exclude='tests/'
    --exclude='docs/'
    # Server-only, never shipped and never deleted:
    --exclude='.env'
    --exclude='.env.*'
    --exclude='.gmail-mcp/'
    --exclude='state/'
    --exclude='database/'
    --exclude='config/'
    --exclude='venv/'
    --exclude='node_modules/'
)

SYNC_LOG="$(mktemp)"
trap 'rm -f "$SYNC_LOG"' EXIT

echo "==> Syncing repo: $REPO_DIR -> $REMOTE_HOST:$REMOTE_DIR"
rsync "${RSYNC_FLAGS[@]}" --delete-after "${EXCLUDES[@]}" \
    -e "ssh -i $SSH_KEY" \
    "$REPO_DIR/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" | tee "$SYNC_LOG"

deleted="$(grep -c '^\*deleting' "$SYNC_LOG" || true)"
[ "${deleted:-0}" = "0" ] || echo "==> Removed $deleted stale remote file(s)"

# Did this push touch a given repo-relative path? --itemize-changes puts the
# path last on every change line.
synced() { awk '{print $NF}' "$SYNC_LOG" | grep -qxF "$1"; }

# Units are synced into a directory this repo does not own, so no --delete here.
echo "==> Syncing systemd units: deploy/hetzner -> $REMOTE_HOST:$SYSTEMD_DIR"
rsync "${RSYNC_FLAGS[@]}" \
    -e "ssh -i $SSH_KEY" \
    "$UNIT_DIR/"*.service "$UNIT_DIR/"*.timer \
    "$REMOTE_USER@$REMOTE_HOST:$SYSTEMD_DIR/"

# The services run as an unprivileged user, not root: two of them are public
# HTTP servers sitting in front of every user's Gmail refresh token. The account
# is created here rather than by hand so a rebuilt box is not silently back on
# root, and the sandbox settings are installed as a drop-in from one file
# (deploy/hetzner/hardening.conf) instead of being repeated in every unit.
echo "==> Ensuring service account and ownership"
remote "id -u $SERVICE_USER >/dev/null 2>&1 || \
    useradd --system --home-dir $REMOTE_DIR --shell /usr/sbin/nologin $SERVICE_USER"
remote "chown -R $SERVICE_USER:$SERVICE_USER $REMOTE_DIR && \
    chmod 750 $REMOTE_DIR && \
    for d in database state .gmail-mcp config; do \
        [ -e $REMOTE_DIR/\$d ] && chmod 700 $REMOTE_DIR/\$d; \
    done; \
    [ -e $REMOTE_DIR/.env ] && chmod 600 $REMOTE_DIR/.env; true"

CONFIG_PRESENT=()
for name in "${CONFIG_FILES[@]}"; do
    if [ -f "$CONFIG_LOCAL/$name" ]; then
        CONFIG_PRESENT+=("$CONFIG_LOCAL/$name")
    else
        echo "==> Config not found locally, leaving remote copy alone: $name"
    fi
done
if [ ${#CONFIG_PRESENT[@]} -gt 0 ]; then
    echo "==> Syncing config -> $REMOTE_HOST:$CONFIG_REMOTE"
    rsync "${RSYNC_FLAGS[@]}" \
        -e "ssh -i $SSH_KEY" \
        "${CONFIG_PRESENT[@]}" "$REMOTE_USER@$REMOTE_HOST:$CONFIG_REMOTE"
fi

# Dependencies before restarts: a unit that gained an import this push must find
# it installed, or the preflight below will (correctly) refuse to start it. The
# spaCy model is a separate one-time install, see requirements.txt.
if synced 'requirements.txt'; then
    echo "==> requirements.txt changed; installing Python deps"
    # `python -m pip`, not `venv/bin/pip`: the latter depends on a shebang that
    # holds the venv's absolute path, which a relocated venv invalidates.
    remote "cd $REMOTE_DIR && venv/bin/python -m pip install --quiet -r requirements.txt"
fi
if synced 'package-lock.json' || synced 'package.json'; then
    echo "==> package manifest changed; installing Node deps"
    remote "cd $REMOTE_DIR && npm install --omit=dev --no-fund --no-audit"
fi

# Services worth restarting are exactly the long-running units (an [Install]
# section); oneshots are driven by their timers. Both lists come from the unit
# files so adding a unit to deploy/hetzner is all it takes to deploy it.
mapfile -t ALL_SERVICES < <(grep -l '^\[Install\]' "$UNIT_DIR"/*.service | xargs -n1 basename)
mapfile -t ALL_TIMERS < <(ls -1 "$UNIT_DIR"/*.timer | xargs -n1 basename)
if [ -n "${SERVICES:-}" ]; then
    read -r -a ALL_SERVICES <<< "$SERVICES"
fi
if [ -n "${TIMERS:-}" ]; then
    read -r -a ALL_TIMERS <<< "$TIMERS"
fi

echo "==> Installing sandbox drop-in for: ${ALL_SERVICES[*]} ${ALL_TIMERS[*]}"
HARDENING="$(cat "$UNIT_DIR/hardening.conf")"
for unit in "${ALL_SERVICES[@]}"; do
    remote "mkdir -p $SYSTEMD_DIR/$unit.d && cat > $SYSTEMD_DIR/$unit.d/10-hardening.conf" \
        <<< "$HARDENING"
done
# Oneshots are launched by their timers and never appear in ALL_SERVICES, so
# they are covered explicitly.
for timer in "${ALL_TIMERS[@]}"; do
    svc="${timer%.timer}.service"
    remote "mkdir -p $SYSTEMD_DIR/$svc.d && cat > $SYSTEMD_DIR/$svc.d/10-hardening.conf" \
        <<< "$HARDENING"
done

echo "==> Reloading systemd"
remote "systemctl daemon-reload"

# A unit whose secrets or deps are not provisioned yet is left alone rather than
# restarted into a crash loop; deploy/preflight.py decides, using the same code
# the services themselves run.
echo "==> Preflight: ${ALL_SERVICES[*]} ${ALL_TIMERS[*]}"
START=()
if [ "$DRY_RUN" = "1" ]; then
    remote "cd $REMOTE_DIR && venv/bin/python -m deploy.preflight ${ALL_SERVICES[*]} ${ALL_TIMERS[*]}"
else
    PREFLIGHT="$(remote "cd $REMOTE_DIR && venv/bin/python -m deploy.preflight ${ALL_SERVICES[*]} ${ALL_TIMERS[*]}")"
    echo "$PREFLIGHT"
    while read -r verdict unit rest; do
        case "$verdict" in
            OK) START+=("${unit}") ;;
            SKIP) echo "    not started: ${unit} ${rest}" >&2 ;;
        esac
    done <<< "$PREFLIGHT"
fi

if [ "$DRY_RUN" = "1" ]; then
    echo "[DRY RUN] not enabling or restarting units"
    echo "==> Done"
    exit 0
fi

if [ ${#START[@]} -eq 0 ]; then
    echo "==> Nothing passed preflight; no unit restarted" >&2
    exit 1
fi

echo "==> Enabling and restarting: ${START[*]}"
remote "systemctl enable ${START[*]} && systemctl restart ${START[*]}"

# systemctl restart returns as soon as the process forks, so a unit that dies on
# startup still looks like a successful deploy. Check the state after the fact.
sleep 3
ACTIVE="$(remote "for u in ${START[*]}; do printf '%s %s\n' \"\$u\" \"\$(systemctl is-active \$u)\"; done")"
echo "$ACTIVE"
if grep -vE ' (active|activating)$' <<< "$ACTIVE"; then
    echo "==> Those units are not running; check journalctl -u <unit>" >&2
    exit 1
fi

echo "==> Done"
