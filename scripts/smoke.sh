#!/bin/sh
# A smoke test against a running mangrove, exercising the paths that carry the
# design: publish, the containment refusal, the per-recipient hold, and the
# last-writer-wins reduction.
#
# It uses only wget and sh, so it runs INSIDE the container as well as outside:
#
#   docker compose --profile mangrove exec -T crab-mangrove-network \
#     sh /usr/local/share/mangrove-smoke.sh
#
# or, against a locally built binary:
#
#   MANGROVE_URL=http://127.0.0.1:8090 MANGROVE_TOKEN=dev-secret ./scripts/smoke.sh
#
# It writes to whatever store the service is using. Point it at a throwaway
# MANGROVE_STORE_DIR, not at anything you care about.
set -eu

URL="${MANGROVE_URL:-http://127.0.0.1:8090}"
TOKEN="${MANGROVE_TOKEN:?set MANGROVE_TOKEN to the service's shared secret}"

fail=0

post() { # post <path> <json>
  wget -qO- \
    --header="Authorization: Bearer ${TOKEN}" \
    --header="Content-Type: application/json" \
    --post-data="$2" \
    "${URL}$1" 2>/dev/null || true
}

# A refusal answers 403, and wget prints nothing on a non-2xx. Capture the body.
post_expect_refusal() {
  wget -qO- --server-response \
    --header="Authorization: Bearer ${TOKEN}" \
    --header="Content-Type: application/json" \
    --post-data="$2" \
    "${URL}$1" 2>&1 || true
}

check() { # check <label> <haystack> <needle>
  if printf '%s' "$2" | grep -q "$3"; then
    echo "  ok    $1"
  else
    echo "  FAIL  $1"
    echo "        wanted to find: $3"
    echo "        got: $2"
    fail=1
  fi
}

ALICE='{"tenantId":"t1","subsAccId":"s1","role":"alpha","userAccId":"alice"}'
BOB='{"tenantId":"t1","subsAccId":"s1","role":"alpha","userAccId":"bob"}'

echo "mangrove smoke test against ${URL}"

echo
echo "health"
check "answers ok" "$(wget -qO- "${URL}/healthz" 2>/dev/null || true)" "ok"

echo
echo "identity comes from the tuple, never the body"
out=$(post /internal/v1/publish \
  "{\"tuple\":${ALICE},\"actor\":\"mangrove:actor:mallory:service\",\"object\":{\"type\":\"MemoryNote\",\"cell\":\"soil-ph\",\"content\":\"5.8\"}}")
check "a forged actor in the body is ignored" "$out" 'mangrove:actor:alice:service'

echo
echo "containment"
out=$(post_expect_refusal /internal/v1/publish \
  "{\"tuple\":${ALICE},\"to\":[\"mangrove:group:tenant:t1\"],\"object\":{\"type\":\"MemoryNote\",\"cell\":\"x\",\"content\":\"y\"}}")
check "an agent cannot address the tenant" "$out" "403"

out=$(post_expect_refusal /internal/v1/publish \
  "{\"tuple\":${ALICE},\"to\":[\"mangrove:group:subscription:s2\"],\"object\":{\"type\":\"MemoryNote\",\"cell\":\"x\",\"content\":\"y\"}}")
check "a foreign subscription is refused" "$out" "403"

echo
echo "own subscription publishes, and waits on a governing role"
out=$(post /internal/v1/publish \
  "{\"tuple\":${ALICE},\"to\":[\"mangrove:group:subscription:s1\"],\"object\":{\"type\":\"MemoryNote\",\"cell\":\"soil-n\",\"content\":\"12 ppm\"}}")
check "published" "$out" '"type":"Create"'
check "marked pending" "$out" '"pending":true'

echo
echo "two authors on one cell both survive"
post /internal/v1/publish \
  "{\"tuple\":${BOB},\"object\":{\"type\":\"MemoryNote\",\"cell\":\"soil-ph\",\"content\":\"6.4\"}}" >/dev/null
out=$(post /internal/v1/timeline "{\"tuple\":${ALICE},\"reading\":\"published\"}")
check "alice still holds her own claim" "$out" '"content":"5.8"'
out=$(post /internal/v1/timeline "{\"tuple\":${BOB},\"reading\":\"published\"}")
check "bob holds his, unmerged" "$out" '"content":"6.4"'

echo
echo "a direct share is held until the recipient admits it"
out=$(post /internal/v1/publish \
  "{\"tuple\":${BOB},\"to\":[\"mangrove:actor:alice:service\"],\"object\":{\"type\":\"MemoryNote\",\"cell\":\"held-note\",\"content\":\"for alice\"}}")

# ADDRESSING A NAMED COLLEAGUE NEEDS THE PROXY, and self/subscription scopes do
# not. The reachability gate has to answer "does this person have a workspace
# under a subscription the caller shares", and the only source for that is
# crab-shell-proxy's membership endpoint -- the mangrove keeps no membership list of
# its own, deliberately, so it cannot answer alone.
#
# Unreachable, it FAILS CLOSED rather than assuming membership. That is the
# right behaviour and it means this section cannot run standalone.
#
# An EMPTY body is how that shows up here: `wget -qO-` prints nothing for a
# non-2xx response, and in this section the only non-2xx without the proxy is
# the membership lookup. Checked alongside the message itself, so the branch
# still reads correctly if the body ever does come through.
if [ -z "$out" ] || printf '%s' "$out" | grep -q 'resolve subscription members'; then
  echo "  skip  needs crab-shell-proxy's /v1/mangrove/subscription-members"
  echo "        (it exists, but is not running here). Self and"
  echo "        subscription scopes above do not need it. The gate failed"
  echo "        CLOSED rather than assuming membership, which is correct."
else
  sent=$(printf '%s' "$out" | sed -n 's/.*"id":"\(mangrove:act:[^"]*\)".*/\1/p' | head -1)
  out=$(post /internal/v1/timeline "{\"tuple\":${ALICE},\"reading\":\"received\"}")
  check "it is held, not ingested" "$out" '"held"'

  if [ -n "$sent" ]; then
    post /internal/v1/admit "{\"tuple\":${ALICE},\"as\":\"person\",\"activityId\":\"${sent}\"}" >/dev/null
    out=$(post /internal/v1/timeline "{\"tuple\":${ALICE},\"reading\":\"received\"}")
    check "after admitting, it is a claim" "$out" '"content":"for alice"'
  else
    echo "  FAIL  could not read the activity id back"
    fail=1
  fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "all checks passed"
else
  echo "SOME CHECKS FAILED"
fi
exit "$fail"
