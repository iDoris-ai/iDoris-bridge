#!/usr/bin/env bash
# Backup and rollback snapshots must surface tar/find failures. A snapshot
# that is not a valid identity archive must not be applied, and must not
# delete the live tailscaled.state.
#
# tailscaled.state is mandatory only inside an archive that claims to hold
# the node identity. These stay successful omissions:
#   - no vpn-sidecar container
#   - no vpn-sidecar-state volume (snapshot writes sidecar-absent "volume")
#   - a volume with no regular tailscaled.state, including a lookalike name
#     such as tailscaled.state.bak (snapshot writes sidecar-absent "file")
#
# The partial-archive fixture is a regular tailscaled.state plus a filename
# that contains a newline. Alpine tar then exits 1 with "Cannot stat" /
# "error exit delayed" after writing a non-empty archive that still contains
# tailscaled.state. The old "tar ...; exit 0" hid that status, and the
# non-empty check accepted the archive.
set -euo pipefail
umask 077

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
root="$repo/deploy/vpn"
alpine="alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"
rand="$(python3 -c 'import random; print(random.randint(100000, 999999))')"
proj="idoris-vpn-f1arc-${rand}"
# Not named vol: copy_sidecar_state locals that name and would hide it.
sid_vol="${proj}_vpn-sidecar-state"
work="$(mktemp -d "${TMPDIR:-/tmp}/idoris-f1arc.XXXXXX")"
live='live-f1-identity'
planted='notes-stay'

die() { echo "f1arc: $*" >&2; exit 1; }

cleanup() {
  docker volume rm -f "$sid_vol" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

command -v docker >/dev/null || die "docker not found"
mkdir -p "$work/here"
printf 'services: {}\n' > "$work/here/compose.yaml"
printf 'COMPOSE_PROJECT_NAME=%s\n' "$proj" > "$work/here/.env"
chmod 600 "$work/here/.env"
# shellcheck disable=SC2034
here="$work/here"
# shellcheck disable=SC1091
source "$root/ops-lib.sh"
export COMPOSE_PROJECT_LOCK="$proj"

# shellcheck disable=SC2317,SC2329
_compose_ps_id() { printf 'cid-f1arc\n'; }
# shellcheck disable=SC2317,SC2329
volume_name_for() { printf '%s\n' "$sid_vol"; }

docker volume create "$sid_vol" >/dev/null

read_identity() {
  docker run --rm --network none -v "${sid_vol}:/data:ro" "$alpine" \
    sh -c 'if [ -f /data/tailscaled.state ]; then cat /data/tailscaled.state; else printf MISSING; fi'
}

notes_flag() {
  docker run --rm --network none -v "${sid_vol}:/data:ro" "$alpine" \
    sh -c 'if [ -f /data/notes.txt ]; then printf NOTES; else printf NO_NOTES; fi'
}

reset_identity() {
  docker run --rm --network none -v "${sid_vol}:/data" -e IDENT="$1" -e NOTES="${2:-}" "$alpine" \
    sh -c 'cd /data && find . -mindepth 1 -depth -exec rm -rf {} +
           printf %s "$IDENT" > /data/tailscaled.state
           if [ -n "$NOTES" ]; then printf %s "$NOTES" > /data/notes.txt; fi'
}

plant_broken_list() {
  docker run --rm --network none -v "${sid_vol}:/data" -e IDENT="$1" "$alpine" \
    sh -c 'cd /data && find . -mindepth 1 -depth -exec rm -rf {} +
           printf %s "$IDENT" > /data/tailscaled.state
           printf x > "/data/$(printf "bad\nname")"'
}

bugs=0
note_bug() {
  echo "BUG: $*" >&2
  bugs=$((bugs + 1))
}

python3 - "$work" <<'PY'
import io, os, sys, tarfile
work = sys.argv[1]
def write(path, members):
    with tarfile.open(path, "w") as handle:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                info.size = 0
                handle.addfile(info)
            else:
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
write(os.path.join(work, "no-identity.tar"), [("notes.txt", b"other-file\n")])
payload = b"R" * 20000
full = os.path.join(work, "large.tar")
write(full, [("tailscaled.state", payload)])
raw = open(full, "rb").read()
open(os.path.join(work, "truncated.tar"), "wb").write(raw[:512 + 100])
write(os.path.join(work, "valid.tar"), [("tailscaled.state", b"restored-f1-identity")])
PY

echo "test: tar failure is not a successful backup"
plant_broken_list "$live"
dest="$work/backup/sidecar/state.tar"
set +e
(
  set -euo pipefail
  copy_sidecar_state "$dest"
) >"$work/backup.out" 2>"$work/backup.err"
backup_rc=$?
set -e
if [[ "$backup_rc" -eq 0 || -s "$dest" ]]; then
  note_bug "backup accepted a partial sidecar archive rc=${backup_rc} bytes=$(wc -c < "$dest" 2>/dev/null || echo 0)"
  cat "$work/backup.err" >&2 || true
else
  echo "ok: backup rejects a partial sidecar archive (rc=${backup_rc})"
fi
got="$(read_identity)"
[[ "$got" == "$live" ]] || note_bug "backup changed live identity to [${got}]"

echo "test: tar failure is not a successful rollback snapshot"
mkdir -p "$work/snap-broken"
# The helper turns set -e back on before returning, so a direct call would
# exit this script. A subshell keeps that failure local.
set +e
(
  _snapshot_sidecar_state "$work/snap-broken"
) >"$work/snap-broken.out" 2>"$work/snap-broken.err"
snap_rc=$?
set -e
if [[ "$snap_rc" -eq 0 || -s "$work/snap-broken/sidecar-state.tar" || -e "$work/snap-broken/sidecar-absent" ]]; then
  note_bug "snapshot treated tar failure as captured or absent rc=${snap_rc}"
  cat "$work/snap-broken.err" >&2 || true
  ls -l "$work/snap-broken" >&2 || true
else
  echo "ok: snapshot rejects a partial sidecar archive (rc=${snap_rc})"
fi
got="$(read_identity)"
[[ "$got" == "$live" ]] || note_bug "snapshot changed live identity to [${got}]"

echo "test: archive without tailscaled.state does not delete the live identity"
reset_identity "$live" "$planted"
mkdir -p "$work/snap-missing"
cp "$work/no-identity.tar" "$work/snap-missing/sidecar-state.tar"
set +e
_restore_sidecar_volume "$work/snap-missing" >"$work/restore-missing.out" 2>"$work/restore-missing.err"
miss_rc=$?
set -e
got="$(read_identity)"
notes="$(notes_flag)"
if [[ "$miss_rc" -eq 0 || "$got" != "$live" || "$notes" != "NOTES" ]]; then
  note_bug "identity-less snapshot applied rc=${miss_rc} identity=[${got}] notes=${notes}"
  cat "$work/restore-missing.err" >&2 || true
else
  echo "ok: identity-less snapshot left the live volume alone (rc=${miss_rc})"
fi

echo "test: truncated archive does not delete the live identity"
reset_identity "$live" "$planted"
mkdir -p "$work/snap-trunc"
cp "$work/truncated.tar" "$work/snap-trunc/sidecar-state.tar"
set +e
_restore_sidecar_volume "$work/snap-trunc" >"$work/restore-trunc.out" 2>"$work/restore-trunc.err"
trunc_rc=$?
set -e
got="$(read_identity)"
notes="$(notes_flag)"
if [[ "$trunc_rc" -eq 0 || "$got" != "$live" || "$notes" != "NOTES" ]]; then
  note_bug "truncated snapshot applied rc=${trunc_rc} identity=[${got}] notes=${notes}"
  cat "$work/restore-trunc.err" >&2 || true
else
  echo "ok: truncated snapshot left the live volume alone (rc=${trunc_rc})"
fi

echo "test: extract refuses an archive without tailscaled.state"
reset_identity "$live" ""
set +e
extract_sidecar_tar "$work/no-identity.tar" >"$work/extract.out" 2>"$work/extract.err"
extract_rc=$?
set -e
got="$(read_identity)"
notes="$(notes_flag)"
if [[ "$extract_rc" -eq 0 || "$got" != "$live" || "$notes" != "NO_NOTES" ]]; then
  note_bug "extract applied an archive without identity rc=${extract_rc} identity=[${got}] notes=${notes}"
  cat "$work/extract.err" >&2 || true
else
  echo "ok: extract refused an archive without identity (rc=${extract_rc})"
fi

if [[ "$bugs" -ne 0 ]]; then
  die "${bugs} sidecar archive bug checks failed"
fi

echo "test: a valid snapshot still replaces the live identity"
reset_identity "$live" "$planted"
mkdir -p "$work/snap-valid"
cp "$work/valid.tar" "$work/snap-valid/sidecar-state.tar"
_restore_sidecar_volume "$work/snap-valid" || die "valid sidecar restore failed"
got="$(read_identity)"
[[ "$got" == "restored-f1-identity" ]] || die "valid restore left [${got}]"
notes="$(notes_flag)"
[[ "$notes" == "NO_NOTES" ]] || die "valid restore kept notes.txt"

echo "test: confirmed absence still removes a planted identity"
reset_identity "$live" ""
rm -f "$work/snap-valid/sidecar-state.tar"
printf 'file\n' > "$work/snap-valid/sidecar-absent"
chmod 600 "$work/snap-valid/sidecar-absent"
_restore_sidecar_volume "$work/snap-valid" || die "confirmed-absent restore failed"
got="$(read_identity)"
[[ "$got" == "MISSING" ]] || die "confirmed absence left [${got}]"

echo "test: a clean volume snapshots and backs up the identity"
reset_identity "$live" ""
mkdir -p "$work/snap-clean"
_snapshot_sidecar_state "$work/snap-clean" || die "clean snapshot failed"
[[ -s "$work/snap-clean/sidecar-state.tar" ]] || die "clean snapshot wrote no archive"
[[ ! -e "$work/snap-clean/sidecar-absent" ]] || die "clean snapshot also recorded absence"
python3 "$root/bundle.py" sidecar-tar "$work/snap-clean/sidecar-state.tar" \
  || die "clean snapshot archive failed validation"
got="$(read_identity)"
[[ "$got" == "$live" ]] || die "clean snapshot changed live identity to [${got}]"
clean_dest="$work/clean-backup/state.tar"
copy_sidecar_state "$clean_dest" || die "clean backup failed"
[[ -s "$clean_dest" ]] || die "clean backup wrote no archive"
python3 "$root/bundle.py" sidecar-tar "$clean_dest" || die "clean backup archive failed validation"

echo "test: no tailscaled.state is omitted, including a lookalike name"
docker run --rm --network none -v "${sid_vol}:/data" "$alpine" \
  sh -c 'cd /data && find . -mindepth 1 -depth -exec rm -rf {} +; printf notes > /data/notes.txt'
empty_dest="$work/empty-backup/state.tar"
set +e
(
  set -euo pipefail
  copy_sidecar_state "$empty_dest"
) >"$work/empty-backup.out" 2>"$work/empty-backup.err"
empty_rc=$?
set -e
[[ "$empty_rc" -eq 0 ]] || die "empty volume backup failed: $(cat "$work/empty-backup.err")"
[[ ! -e "$empty_dest" ]] || die "empty volume backup wrote an archive"
grep -q 'no tailscaled.state' "$work/empty-backup.err" || die "empty volume backup did not say why: $(cat "$work/empty-backup.err")"
mkdir -p "$work/snap-empty"
_snapshot_sidecar_state "$work/snap-empty" || die "empty volume snapshot failed"
[[ ! -e "$work/snap-empty/sidecar-state.tar" ]] || die "empty volume snapshot wrote an archive"
[[ "$(cat "$work/snap-empty/sidecar-absent")" == "file" ]] || die "empty volume absence marker is [$(cat "$work/snap-empty/sidecar-absent" 2>/dev/null || true)]"

docker run --rm --network none -v "${sid_vol}:/data" "$alpine" \
  sh -c 'cd /data && find . -mindepth 1 -depth -exec rm -rf {} +; printf bak > /data/tailscaled.state.bak'
like_dest="$work/like-backup/state.tar"
set +e
(
  set -euo pipefail
  copy_sidecar_state "$like_dest"
) >"$work/like-backup.out" 2>"$work/like-backup.err"
like_rc=$?
set -e
[[ "$like_rc" -eq 0 ]] || die "lookalike backup failed: $(cat "$work/like-backup.err")"
[[ ! -e "$like_dest" ]] || die "lookalike backup wrote an archive"
grep -q 'no tailscaled.state' "$work/like-backup.err" || die "lookalike backup did not omit: $(cat "$work/like-backup.err")"
mkdir -p "$work/snap-like"
_snapshot_sidecar_state "$work/snap-like" || die "lookalike snapshot failed"
[[ ! -e "$work/snap-like/sidecar-state.tar" ]] || die "lookalike snapshot wrote an archive"
[[ "$(cat "$work/snap-like/sidecar-absent")" == "file" ]] || die "lookalike absence marker is [$(cat "$work/snap-like/sidecar-absent" 2>/dev/null || true)]"

echo "test: a nested tailscaled.state is still an identity archive"
docker run --rm --network none -v "${sid_vol}:/data" -e IDENT="$live" "$alpine" \
  sh -c 'cd /data && find . -mindepth 1 -depth -exec rm -rf {} +
         mkdir -p /data/sub
         printf %s "$IDENT" > /data/sub/tailscaled.state'
mkdir -p "$work/snap-nested"
_snapshot_sidecar_state "$work/snap-nested" || die "nested snapshot failed"
[[ -s "$work/snap-nested/sidecar-state.tar" ]] || die "nested snapshot wrote no archive"
python3 "$root/bundle.py" sidecar-tar "$work/snap-nested/sidecar-state.tar" \
  || die "nested snapshot archive failed validation"

echo "test: no sidecar volume is confirmed absence, not an error"
novol_proj="idoris-vpn-f1novol-${rand}"
export COMPOSE_PROJECT_LOCK="$novol_proj"
mkdir -p "$work/snap-novol"
_snapshot_sidecar_state "$work/snap-novol" || die "missing volume snapshot failed"
[[ ! -e "$work/snap-novol/sidecar-state.tar" ]] || die "missing volume wrote an archive"
[[ "$(cat "$work/snap-novol/sidecar-absent")" == "volume" ]] || die "missing volume marker is [$(cat "$work/snap-novol/sidecar-absent" 2>/dev/null || true)]"
export COMPOSE_PROJECT_LOCK="$proj"

echo "test: no sidecar container omits backup state"
# shellcheck disable=SC2317
_compose_ps_id() { :; }
none_dest="$work/none-backup/state.tar"
copy_sidecar_state "$none_dest" || die "containerless backup failed"
[[ ! -e "$none_dest" ]] || die "containerless backup wrote an archive"

echo "test_sidecar_archive_errors: ok"
