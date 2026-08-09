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

# The web UI runs as its own account (deploy/hetzner/letterlock-web.service.d),
# so "owner only" stopped being an answer for the files two uids share. Which
# group holds what is decided in backend/paths.py, because the application sets
# these modes at runtime too and the two must agree; read back from there rather
# than spelled twice.
DATA_GROUP="$(cd "$REPO_DIR" && python3 -c 'from backend import paths; print(paths.DATA_GROUP)')"
SECRETS_GROUP="$(cd "$REPO_DIR" && python3 -c 'from backend import paths; print(paths.SECRETS_GROUP)')"
WAKE_GROUP="$(cd "$REPO_DIR" && python3 -c 'from backend import paths; print(paths.WAKE_GROUP)')"
BILLING_QUEUE_GROUP="$(cd "$REPO_DIR" && python3 -c 'from backend import paths; print(paths.BILLING_QUEUE_GROUP)')"
BILLING_SECRETS_GROUP="$(cd "$REPO_DIR" && python3 -c 'from backend import paths; print(paths.BILLING_SECRETS_GROUP)')"
SHARED_GROUPS=("$DATA_GROUP" "$SECRETS_GROUP" "$WAKE_GROUP" "$BILLING_QUEUE_GROUP" "$BILLING_SECRETS_GROUP")
for g in "${SHARED_GROUPS[@]}"; do
    [ -n "$g" ] || { echo "could not read group names from backend/paths.py" >&2; exit 1; }
done
echo "==> Ensuring shared groups: ${SHARED_GROUPS[*]}"
for group in "${SHARED_GROUPS[@]}"; do
    remote "getent group $group >/dev/null || groupadd --system $group"
    # The mail units run as SERVICE_USER, which has no drop-in to name its
    # supplementary groups. Membership matters beyond reading: paths.shared_dir
    # hands a directory to the group, and chgrp by a non-root owner is refused
    # unless the owner is in the target group.
    remote "id -nG $SERVICE_USER | tr ' ' '\n' | grep -qx $group || \
        usermod -aG $group $SERVICE_USER"
done

# database/, state/ and config/ are setgid to the shared group so a file created
# by either uid is readable by the other; .gmail-mcp/ deliberately is not, since
# it holds the OAuth client secret and the web tier receives the authorization
# code that secret would exchange. token.bin is put back to owner-only after the
# blanket pass: it is the one file the web tier must not read, because the data
# key it legitimately holds for a document render would open it.
#
# The two spools are the other exceptions and they move sideways rather than
# down. The wake files (FIFO plus its spool) go to WAKE_GROUP and the billing
# spool to BILLING_QUEUE_GROUP, each holding the mail uid and one receiver.
# Writing to the wake path starts a drafting pass against a named account and
# spends that account's co-signer budget, so it is a capability the web uid and
# the billing uid are kept out of even though both are in DATA_GROUP.
#
# state/ is 2771 rather than 2770 and database/ is not: four uids open a file in
# state/ and they are deliberately not all in one group, so traversal has to be
# open for a file's own mode to be the grant. Every file in there is 0600 or
# 0660 to a named group, and x without r is not listing. Who has an account is
# itself worth keeping, which is why database/ does not get the same bit.
remote "chown -R $SERVICE_USER:$SERVICE_USER $REMOTE_DIR && \
    chmod 750 $REMOTE_DIR && \
    [ -e $REMOTE_DIR/.gmail-mcp ] && chmod 700 $REMOTE_DIR/.gmail-mcp; \
    for d in database state; do \
        [ -e $REMOTE_DIR/\$d ] || continue; \
        chgrp -R $DATA_GROUP $REMOTE_DIR/\$d; \
        find $REMOTE_DIR/\$d -type d -exec chmod 2770 {} +; \
        find $REMOTE_DIR/\$d -type f -exec chmod 660 {} +; \
    done; \
    [ -e $REMOTE_DIR/state ] && chmod 2771 $REMOTE_DIR/state; \
    [ -e $REMOTE_DIR/database ] && \
        find $REMOTE_DIR/database -type f -name token.bin -exec chmod 600 {} +; \
    for f in wake.fifo wake_queue.jsonl wake_queue.lock; do \
        [ -e $REMOTE_DIR/state/\$f ] || continue; \
        chgrp $WAKE_GROUP $REMOTE_DIR/state/\$f && chmod 660 $REMOTE_DIR/state/\$f; \
    done; \
    for f in billing_queue.jsonl billing_queue.lock; do \
        [ -e $REMOTE_DIR/state/\$f ] || continue; \
        chgrp $BILLING_QUEUE_GROUP $REMOTE_DIR/state/\$f && chmod 660 $REMOTE_DIR/state/\$f; \
    done; \
    if [ -e $REMOTE_DIR/config ]; then \
        chgrp -R $DATA_GROUP $REMOTE_DIR/config; \
        find $REMOTE_DIR/config -type d -exec chmod 2750 {} +; \
        find $REMOTE_DIR/config -type f -exec chmod 640 {} +; \
    fi; \
    [ -e $REMOTE_DIR/.env ] && chgrp $SECRETS_GROUP $REMOTE_DIR/.env && \
        chmod 640 $REMOTE_DIR/.env; \
    [ -e $REMOTE_DIR/.env.billing ] && \
        chgrp $BILLING_SECRETS_GROUP $REMOTE_DIR/.env.billing && \
        chmod 640 $REMOTE_DIR/.env.billing; true"

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
# Read per drop-in rather than over their concatenation, because the groups a
# unit's account belongs to are now part of the same answer: SupplementaryGroups=
# in the drop-in is the only statement of which accounts reach the account store
# and which reach only the source. Making it so here means the unit file is that
# statement instead of describing one somebody applied by hand.
for conf in "$UNIT_DIR"/*.d/*.conf; do
    [ -f "$conf" ] || continue
    account="$(sed -n 's/^User=[[:space:]]*//p' "$conf" | tail -1)"
    [ -n "$account" ] || continue
    if [ "$account" != "$SERVICE_USER" ]; then
        echo "==> Ensuring service account: $account"
        # No home and no shell: it owns its StateDirectory and its credentials,
        # and reaches the source read-only through SupplementaryGroups=.
        remote "id -u $account >/dev/null 2>&1 || \
            useradd --system --no-create-home --shell /usr/sbin/nologin $account"
    fi
    for group in $(sed -n 's/^SupplementaryGroups=[[:space:]]*//p' "$conf"); do
        remote "getent group $group >/dev/null || groupadd --system $group"
        remote "id -nG $account | tr ' ' '\n' | grep -qx $group || \
            usermod -aG $group $account"
    done
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
