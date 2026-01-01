#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARTIFACTS="$ROOT/tests/artifacts"
LOG="$ARTIFACTS/demo.log"
mkdir -p "$ARTIFACTS"
: > "$LOG"

KATHARA_BIN=${KATHARA_BIN:-kathara}

# API path (controller)
API_PATH="/api/firewall"

red()   { printf "\e[31m%s\e[0m\n" "$*"; }
green() { printf "\e[32m%s\e[0m\n" "$*"; }
info()  { echo "[INFO] $*" | tee -a "$LOG"; }
pass()  { green "[PASS] $*" | tee -a "$LOG"; }
fail()  { red "[FAIL] $*" | tee -a "$LOG"; exit 1; }

# ✅ IMPORTANT: Kathara commands MUST run in $ROOT (where lab.conf is)
kathara() {
  ( cd "$ROOT" && "$KATHARA_BIN" "$@" )
}

run_node() {
  local node="$1"; shift
  # capture stderr so we see real errors (e.g., "No lab.conf")
  kathara exec "$node" -- bash -lc "$*" 2> >(tee -a "$ARTIFACTS/stderr_${node}.log" >&2)
}

# --- API check: prefer inside ctrl using localhost ---
probe_api_in_ctrl() {
  # try localhost inside ctrl (most reliable)
  run_node ctrl "curl -sf --max-time 2 http://127.0.0.1:8080${API_PATH}/status" \
    > "$ARTIFACTS/status_boot.json"
}

wait_api() {
  info "Waiting controller API (lab must be already running) via ctrl: http://127.0.0.1:8080${API_PATH}/status"
  local retries=20
  until probe_api_in_ctrl; do
    ((retries--)) || {
      info "---- DEBUG ctrl networking ----"
      run_node ctrl "ip a"        > "$ARTIFACTS/ctrl_ip_a.txt" || true
      run_node ctrl "ip r"        > "$ARTIFACTS/ctrl_ip_r.txt" || true
      run_node ctrl "ss -lntp"    > "$ARTIFACTS/ctrl_ss_lntp.txt" || true
      run_node ctrl "ps aux | head -n 50" > "$ARTIFACTS/ctrl_ps.txt" || true
      fail "API not reachable inside ctrl on 127.0.0.1:8080 (see artifacts/*ctrl*)"
    }
    sleep 2
  done
  pass "Controller API reachable inside ctrl (localhost:8080)"
}

assert_event() {
  local type="$1"; local outfile="$2"
  run_node ctrl "curl -sf http://127.0.0.1:8080${API_PATH}/events?limit=200" > "$outfile"
  python3 - <<PY
import json,sys
payload=json.load(open("$outfile"))
found=any(ev.get("type")== "$type" for ev in payload.get("events",[]))
sys.exit(0 if found else 1)
PY
  pass "Event $type present"
}

# ------------------ TEST STEPS ------------------

step_baseline_mqtt() {
  info "Baseline MQTT allow (inside client)"
  run_node h_client "timeout 8s sh -c 'mosquitto_sub -C 1 -h 10.0.11.20 -t demo/test > /tmp/sub.out & sleep 1; mosquitto_pub -h 10.0.11.20 -t demo/test -m hello'" \
    || fail "MQTT pub/sub failed"
  run_node h_client "cat /tmp/sub.out" > "$ARTIFACTS/mqtt_baseline.log"
  pass "MQTT allowed for inside client"
}

step_deny_outside() {
  info "MQTT deny from outside"
  if run_node h_out "timeout 6s nc -vz 10.0.11.20 1883"; then
    fail "Outside host unexpectedly reached MQTT"
  else
    pass "Outside host blocked on MQTT"
  fi
}

step_portscan() {
  info "Trigger port-scan detection"
  run_node h_out "nmap -Pn -p 1800-1815 10.0.11.20" > "$ARTIFACTS/portscan.log" || true
  sleep 3
  assert_event "PORTSCAN_DETECTED" "$ARTIFACTS/events_portscan.json"
}

step_dos() {
  info "Trigger DoS detection"
  run_node h_out "timeout 5s hping3 -S -p 1883 --faster 10.0.11.20" > "$ARTIFACTS/dos.log" || true
  sleep 3
  assert_event "DOS_DETECTED" "$ARTIFACTS/events_dos.json"
}

step_syn_flood() {
  info "Trigger SYN flood detection"
  run_node h_out "timeout 4s hping3 -S -p 8883 --flood 10.0.11.20" > "$ARTIFACTS/synflood.log" || true
  sleep 3
  assert_event "SYN_FLOOD_DETECTED" "$ARTIFACTS/events_syn.json"
}

step_patterns() {
  info "Trigger suspicious patterns (MQTT storm + XMAS)"
  run_node h_out "for i in \$(seq 1 12); do nc -z -w1 10.0.11.20 1883 || true; done" > "$ARTIFACTS/mqtt_storm.log" || true
  sleep 2
  assert_event "SUSPICIOUS_PATTERN" "$ARTIFACTS/events_pattern1.json"

  run_node h_out "nmap -sX -Pn -p 1883 10.0.11.20" > "$ARTIFACTS/xmas_scan.log" || true
  sleep 2
  assert_event "SUSPICIOUS_PATTERN" "$ARTIFACTS/events_pattern2.json"
}

step_collect() {
  info "Collecting flow dump and status"
  run_node s1 "ovs-ofctl -O OpenFlow13 dump-flows br0" > "$ARTIFACTS/flows.txt"
  run_node ctrl "curl -sf http://127.0.0.1:8080${API_PATH}/status" > "$ARTIFACTS/status_final.json"
  pass "Artifacts written to $ARTIFACTS"
}

main() {
  info "Running attack/demo tests (lab must already be running)"
  wait_api
  step_baseline_mqtt
  step_deny_outside
  step_portscan
  step_dos
  step_syn_flood
  step_patterns
  step_collect
  pass "Demo completed"
}

main "$@"
