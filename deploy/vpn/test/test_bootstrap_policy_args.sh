#!/usr/bin/env bash
# Verify bootstrap passes the checked-in Headscale config to policy.py without Docker.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/headscale" "$tmp/headplane" "$tmp/bin"
cp "$root/bootstrap.sh" "$tmp/bootstrap.sh"
cp "$root/headscale/policy.hujson" "$tmp/headscale/policy.hujson"
sed 's/vpn\.example\.org/vpn.test/g' "$root/headscale/config.yaml" > "$tmp/headscale/config.yaml"
sed 's/vpn\.example\.org/vpn.test/g' "$root/headplane/config.yaml" > "$tmp/headplane/config.yaml"

cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == compose && "$2" == version ]]
EOF
cat > "$tmp/bin/python3" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$CIDR_TEST_CAPTURE"
exit 1
EOF
chmod +x "$tmp/bin/docker" "$tmp/bin/python3"

export CIDR_TEST_CAPTURE="$tmp/args"
if PATH="$tmp/bin:$PATH" bash "$tmp/bootstrap.sh" init --org acme --lan-cidr 10.20.0.0/16 > "$tmp/stdout" 2> "$tmp/stderr"; then
  echo "bootstrap unexpectedly passed the policy render stub" >&2
  exit 1
fi
[[ -s "$CIDR_TEST_CAPTURE" ]] || { cat "$tmp/stderr" >&2; exit 1; }
expect_path=0
while IFS= read -r arg; do
  if (( expect_path )); then
    [[ "$arg" == "$tmp/headscale/config.yaml" ]] || exit 1
    echo "bootstrap Headscale config argument: passed"
    exit 0
  fi
  if [[ "$arg" == --headscale-config ]]; then
    expect_path=1
  fi
done < "$CIDR_TEST_CAPTURE"
echo "bootstrap omitted --headscale-config" >&2
exit 1
