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
    --exclude='.github/'
    --exclude='requirements-dev.txt'
    # Server-only, never shipped and never deleted:
    --exclude='.env'
    --exclude='.env.*'
    --exclude='.gmail-mcp/'
    --exclude='state/'
    --exclude='database/'
    --exclude='config/'
    --exclude='venv/'
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
# spaCy model is a separate one-time install, see requirements.txt. There is no
# npm branch any more: Gmail and Calendar are called from Python, so the box
# runs one language and one dependency tree.
if synced 'requirements.txt'; then
    echo "==> requirements.txt changed; installing Python deps"
    # `python -m pip`, not `venv/bin/pip`: the latter depends on a shebang that
    # holds the venv's absolute path, which a relocated venv invalidates.
    remote "cd $REMOTE_DIR && venv/bin/python -m pip install --quiet -r requirements.txt"
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

# Every unit that gets a sandbox: the long-running services, plus the oneshot
# behind each timer (oneshots have no [Install] and never appear in
# ALL_SERVICES).
SANDBOXED=("${ALL_SERVICES[@]}")
for timer in "${ALL_TIMERS[@]}"; do
    SANDBOXED+=("${timer%.timer}.service")
done

echo "==> Installing sandbox drop-in for: ${SANDBOXED[*]}"
HARDENING="$(cat "$UNIT_DIR/hardening.conf")"
for unit in "${SANDBOXED[@]}"; do
    remote "mkdir -p $SYSTEMD_DIR/$unit.d && cat > $SYSTEMD_DIR/$unit.d/10-hardening.conf" \
        <<< "$HARDENING"
done

# A unit that needs to differ from the common sandbox says so in
# deploy/hetzner/<unit>.d/*.conf, numbered above 10-hardening.conf so it wins.
# One unit's exception belongs beside that unit, not in a weakened hardening.conf
# that every other unit then inherits.
#
# A drop-in may name its own account: the co-signer holds the outer wrapping key
# and the DPoP key, which the application must never be able to read, so it does
# not run as the application's user. The account name is defined in the drop-in
# and nowhere else -- this script reads it back out rather than hardcoding it,
# so adding a second isolated unit needs no change here.
mapfile -t EXTRA_USERS < <(cat "$UNIT_DIR"/*.d/*.conf 2>/dev/null \
    | sed -n 's/^User=[[:space:]]*//p' | sort -u | grep -vx "$SERVICE_USER" || true)
for account in "${EXTRA_USERS[@]}"; do
    [ -n "$account" ] || continue
    echo "==> Ensuring service account: $account"
    # No home and no shell: it owns its StateDirectory and its credentials, and
    # reaches the source read-only through SupplementaryGroups=.
    remote "id -u $account >/dev/null 2>&1 || \
        useradd --system --no-create-home --shell /usr/sbin/nologin $account"
done

for unit in "${SANDBOXED[@]}"; do
    KEEP="10-hardening.conf"
    for conf in "$UNIT_DIR/$unit.d/"*.conf; do
        [ -f "$conf" ] || continue
        echo "==> Installing $(basename "$conf") for $unit"
        remote "mkdir -p $SYSTEMD_DIR/$unit.d && cat > $SYSTEMD_DIR/$unit.d/$(basename "$conf")" \
            < "$conf"
        KEEP="$KEEP $(basename "$conf")"
    done
    # The repo is authoritative here as it is for the app directory. A drop-in
    # the repo no longer has is a setting that still runs and that nobody can
    # read in git -- for these files that means a unit quietly left on the wrong
    # user or the wrong sandbox.
    remote "KEEP=' $KEEP '; cd $SYSTEMD_DIR/$unit.d 2>/dev/null || exit 0; \
        for f in *.conf; do [ -e \"\$f\" ] || continue; \
            case \"\$KEEP\" in *\" \$f \"*) ;; \
                *) rm -f \"\$f\" && echo \"removed stale drop-in $unit.d/\$f\" ;; \
            esac; done"
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

# The egress allowlist is the one control on this box whose absence looks
# exactly like its presence: IPAddressDeny needs cgroup v2 with BPF, and on a
# kernel without it systemd logs a line and starts the unit anyway, so every
# service comes up healthy with the whole internet reachable. A green restart
# is not evidence, so the deploy asks the running box directly. Failing here
# does not roll anything back -- the units are up and working -- but it is the
# difference between a control and a config file that describes one.
echo "==> Verifying egress enforcement"
if ! remote "cd $REMOTE_DIR && venv/bin/python -m deploy.check_egress"; then
    echo "==> Egress allowlist is NOT being enforced; see above" >&2
    exit 1
fi

echo "==> Done"
