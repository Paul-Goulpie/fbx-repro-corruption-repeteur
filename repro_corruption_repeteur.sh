#!/usr/bin/env bash
# Reproduce silent TCP payload corruption through a Freebox Wi-Fi repeater (fbxwmr-r3).
#
# The client streams a deterministic pseudo-random file (ChaCha20 keystream) over raw TCP
# (socat, no SSH/TLS) to a server wired to the Freebox Server. The server regenerates the
# same file locally and compares both byte by byte. Any difference is data that was altered
# in transit while still carrying a valid TCP checksum.
#
# Requirements:
#   client : bash, socat, openssl, ssh, iw (optional), nmcli (optional, for -b/-c),
#            pv (optional, nicer progress bar; falls back to dd status=progress)
#   server : socat, openssl, cmp, od, ss, passwordless SSH access from the client
#            (sudo + firewalld only if -f is used)

set -euo pipefail

# Traps must only act in the main process, never in pipeline subshells.
MAIN_PID=$BASHPID

usage() {
    cat <<EOF
Usage: $0 -s <ssh_target> [-a <server_ip>] [options]

  -s <ssh_target>  SSH destination of the wired server (e.g. user@server)
  -a <server_ip>   server IPv4 LAN address used for the data stream (default: IPv4 address
                   of the SSH host name; must be a private address, otherwise the stream
                   would go through the box NAT instead of the LAN path under test)
  -i <iface>       client Wi-Fi interface to bind the stream to (e.g. wlan0)
  -b <bssid>       force association to this BSSID (repeater fronthaul), requires -c
  -c <connection>  NetworkManager connection name used with -b
  -n <runs>        number of transfers (default: 8)
  -z <size>        size of each transfer, head -c syntax (default: 2G)
  -p <port>        TCP port (default: 5999)
  -d <remote_dir>  parent directory for work files on the server (default: server \$HOME,
                   needs 2 x <size> free space; avoid a small tmpfs /tmp)
  -f               temporarily open the port in firewalld on the server (uses sudo)
  -h               show this help

Exit status: 0 = no corruption, 1 = corruption detected, 2 = usage/setup error,
             129/130/143 = interrupted (SIGHUP/Ctrl-C/SIGTERM); initial state is restored.
EOF
}

SSH_TARGET=""; SERVER_IP=""; IFACE=""; BSSID=""; CONN=""
RUNS=8; SIZE=2G; PORT=5999; OPEN_FW=0; REMOTE_PARENT='$HOME'

while getopts "s:a:i:b:c:n:z:p:d:fh" opt; do
    case "$opt" in
        s) SSH_TARGET=$OPTARG ;;
        a) SERVER_IP=$OPTARG ;;
        i) IFACE=$OPTARG ;;
        b) BSSID=$OPTARG ;;
        c) CONN=$OPTARG ;;
        n) RUNS=$OPTARG ;;
        z) SIZE=$OPTARG ;;
        p) PORT=$OPTARG ;;
        d) REMOTE_PARENT=$OPTARG ;;
        f) OPEN_FW=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

[[ -n $SSH_TARGET ]] || { usage; exit 2; }
[[ -z $BSSID || -n $CONN ]] || { echo "error: -b requires -c" >&2; exit 2; }
for cmd in socat openssl ssh; do
    command -v "$cmd" >/dev/null || { echo "error: $cmd not found" >&2; exit 2; }
done

is_private_ipv4() { [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; }

if [[ -z $SERVER_IP ]]; then
    # Resolve the real host name behind the SSH target (handles user@host and ~/.ssh/config aliases).
    ssh_host=$(ssh -G "$SSH_TARGET" 2>/dev/null | awk '/^hostname /{h = $2} END {print h}')
    SERVER_IP=$(getent ahostsv4 "${ssh_host:-${SSH_TARGET#*@}}" | awk 'NR == 1 {print $1}')
    [[ -n $SERVER_IP ]] || { echo "error: cannot resolve an IPv4 address for '$SSH_TARGET'; use -a" >&2; exit 2; }
    if ! is_private_ipv4 "$SERVER_IP"; then
        echo "error: '$SSH_TARGET' resolves to $SERVER_IP, which is not a private LAN address;" >&2
        echo "       the test stream would go through the box NAT. Pass the server LAN IP with -a." >&2
        exit 2
    fi
    echo "[$(date +%H:%M:%S)] data stream target: $SERVER_IP (resolved from '$SSH_TARGET')"
elif ! is_private_ipv4 "$SERVER_IP"; then
    echo "[$(date +%H:%M:%S)] warning: $SERVER_IP is not a private address, the stream may not stay on the LAN" >&2
fi

# Deterministic generator: same command on client and server yields identical bytes.
GEN="head -c $SIZE /dev/zero | openssl enc -chacha20 \
-K 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
-iv 00000000000000000000000000000000 2>/dev/null"

RDIR=""; LISTENER_PID=""; SENDER_PID=""; ORIG_BSSID=""; KEEP_REMOTE=0
BSSID_CHANGED=0; FW_OPENED=0; REMOTE_STARTED=0

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# Any unexpected failure is a setup/runtime error, never a corruption result.
trap 'rc=$?; if [[ $BASHPID == "$MAIN_PID" ]]; then echo "[$(date +%H:%M:%S)] error: command failed (status $rc) at line $LINENO: $BASH_COMMAND" >&2; exit 2; fi' ERR

wifi_info() {
    [[ -n $IFACE ]] && command -v iw >/dev/null || { echo "n/a"; return; }
    iw dev "$IFACE" link | awk '/Connected/{b=$3} /signal/{s=$2" dBm"} /tx bitrate/{$1=$2="";t=$0}
        END{printf "bssid=%s signal=%s tx=%s", b, s, t}'
}

# Teardown: runs on every exit path (normal end, error, Ctrl-C, SIGTERM, SIGHUP).
# Each step is guarded by a flag set just before the matching setup step, so only
# what was actually changed is restored, and every step is attempted even if one fails.
CLEANED=0
cleanup() {
    local rc=$?
    [[ $BASHPID == "$MAIN_PID" ]] || return 0
    (( CLEANED )) && return
    CLEANED=1
    trap - ERR
    trap '' INT TERM HUP    # do not let a second Ctrl-C interrupt the restore
    set +e
    (( rc >= 128 )) && log "interrupted (signal $((rc - 128))), restoring initial state..."

    [[ -n $SENDER_PID ]] && kill "$SENDER_PID" 2>/dev/null
    [[ -n $LISTENER_PID ]] && kill "$LISTENER_PID" 2>/dev/null
    if (( REMOTE_STARTED )); then
        # Stop any receiver/generator left running on the server ([x] keeps pkill from matching itself).
        ssh "$SSH_TARGET" "pkill -f '[s]ocat -u TCP4-LISTEN:$PORT,'; pkill -f '[o]penssl enc -chacha20 -K 000102030405'" 2>/dev/null
    fi
    if [[ -n $RDIR ]]; then
        if (( KEEP_REMOTE )); then
            ssh "$SSH_TARGET" "rm -f '$RDIR/rx.bin'"
            log "corrupted copy kept on server: $RDIR/rx_corrupt.bin (reference: $RDIR/ref.bin)"
        else
            ssh "$SSH_TARGET" "rm -rf '$RDIR'" && log "server work directory removed"
        fi
    fi
    if (( FW_OPENED )); then
        ssh "$SSH_TARGET" "sudo firewall-cmd -q --remove-port=$PORT/tcp" && log "firewall port $PORT/tcp closed"
    fi
    if (( BSSID_CHANGED )); then
        log "restoring BSSID setting of '$CONN' to '${ORIG_BSSID:-<none>}'"
        sudo nmcli con modify "$CONN" 802-11-wireless.bssid "$ORIG_BSSID"
        sudo nmcli con up "$CONN" >/dev/null
    fi
    exit "$rc"
}
trap cleanup EXIT
# Convert signals into a normal exit so the EXIT trap always runs (exit status 128 + signal).
trap '[[ $BASHPID == "$MAIN_PID" ]] && exit 130' INT
trap '[[ $BASHPID == "$MAIN_PID" ]] && exit 143' TERM
trap '[[ $BASHPID == "$MAIN_PID" ]] && exit 129' HUP

SIZE_BYTES=$(numfmt --from=iec "$SIZE")

# Refuse concurrent runs: a second instance would hijack the BSSID lock and the TCP port.
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/repro_corruption_repeteur.lock"
flock -n 9 || { echo "error: another instance of this script is already running on this machine" >&2; exit 2; }
if ssh "$SSH_TARGET" "ss -ltn | grep -q ':$PORT '"; then
    echo "error: TCP port $PORT is already in use on the server (another test running?); use -p" >&2
    exit 2
fi

if [[ -n $BSSID ]]; then
    ORIG_BSSID=$(nmcli -g 802-11-wireless.bssid con show "$CONN" | tr -d '\\')
    log "forcing '$CONN' onto BSSID $BSSID"
    BSSID_CHANGED=1
    sudo nmcli con modify "$CONN" 802-11-wireless.bssid "$BSSID"
    sudo nmcli con up "$CONN" >/dev/null
    until ping -c1 -W1 "$SERVER_IP" >/dev/null 2>&1; do sleep 1; done
fi

if (( OPEN_FW )); then
    FW_OPENED=1
    ssh "$SSH_TARGET" "sudo firewall-cmd -q --add-port=$PORT/tcp"
fi

REMOTE_STARTED=1
RDIR=$(ssh "$SSH_TARGET" "mktemp -d \"$REMOTE_PARENT/fbxrepro.XXXXXX\"")
avail=$(ssh "$SSH_TARGET" "df -B1 --output=avail '$RDIR' | tail -1")
if (( avail < 2 * SIZE_BYTES + 100000000 )); then
    echo "error: not enough space in $RDIR on server ($((avail / 1000000)) MB free, $((2 * SIZE_BYTES / 1000000)) MB needed); use -d" >&2
    exit 2
fi
log "server work directory: $RDIR ($((avail / 1000000000)) GB free)"
log "generating $SIZE reference file on server ($RDIR/ref.bin)"
ssh "$SSH_TARGET" "$GEN > '$RDIR/ref.bin'"
EXPECTED=$(ssh "$SSH_TARGET" "stat -c %s '$RDIR/ref.bin'")

BIND=""; [[ -n $IFACE ]] && BIND=",so-bindtodevice=$IFACE"
TIMEOUT=7200

# Progress meter on the sending side, only when stderr is a terminal.
progress() {
    if [[ ! -t 2 ]]; then
        cat
    elif command -v pv >/dev/null; then
        pv -petrab -s "$SIZE_BYTES"
    else
        dd bs=1M iflag=fullblock status=progress
    fi
}
corrupted=0

for ((n = 1; n <= RUNS; n++)); do
    ssh "$SSH_TARGET" "rm -f '$RDIR/rx.bin'; timeout $TIMEOUT socat -u TCP4-LISTEN:$PORT,reuseaddr - > '$RDIR/rx.bin'" &
    LISTENER_PID=$!
    until ssh "$SSH_TARGET" "ss -ltn | grep -q ':$PORT '"; do sleep 1; done

    log "run $n/$RUNS: sending $SIZE to $SERVER_IP:$PORT ..."
    start=$(date +%s)
    # Run in background and wait, so that signals are handled immediately (not after the transfer).
    bash -c "$GEN" | progress | timeout "$TIMEOUT" socat -u - "TCP4:$SERVER_IP:$PORT$BIND" &
    SENDER_PID=$!
    send_rc=0
    wait "$SENDER_PID" || send_rc=$?
    SENDER_PID=""
    # socat exit status is the pipeline status (pipefail); 141 = SIGPIPE upstream, also a failure here.
    (( send_rc == 0 )) || log "warning: sender exited with status $send_rc (connection refused/reset?)"
    # The receiver ends when the connection closes; never wait for it more than 60 s.
    for ((i = 0; i < 60; i++)); do kill -0 "$LISTENER_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$LISTENER_PID" 2>/dev/null; then
        log "warning: receiver still running 60 s after the sender stopped, killing it"
        kill "$LISTENER_PID" 2>/dev/null || true
        ssh "$SSH_TARGET" "pkill -f '[s]ocat -u TCP4-LISTEN:$PORT,'" || true
    fi
    [[ -t 2 ]] && echo >&2
    wait "$LISTENER_PID" || true
    LISTENER_PID=""
    elapsed=$(( $(date +%s) - start ))

    received=$(ssh "$SSH_TARGET" "stat -c %s '$RDIR/rx.bin'")
    diff=$(ssh "$SSH_TARGET" "cmp -l -n $received '$RDIR/ref.bin' '$RDIR/rx.bin' | wc -l")
    rate=$(( received / 1000000 / (elapsed > 0 ? elapsed : 1) ))
    log "run $n/$RUNS: $diff bytes differ, $received/$EXPECTED bytes received in ${elapsed}s (~${rate} MB/s) [$(wifi_info)]"
    (( received == EXPECTED )) || log "warning: transfer incomplete (connection reset or timeout)"

    if (( diff > 0 )); then
        corrupted=1
        log "CORRUPTION DETECTED - altered blocks (stream offset, length):"
        # Group consecutive differing bytes (cmp offsets are 1-based) into blocks.
        ssh "$SSH_TARGET" "cmp -l -n $received '$RDIR/ref.bin' '$RDIR/rx.bin' | awk '
            { o = \$1 - 1 }
            NR == 1 || o > last + 16 { if (NR > 1) print start, last - start + 1; start = o }
            { last = o }
            END { print start, last - start + 1 }'" | while read -r off len; do
            echo "  offset $off, $len bytes"
        done
        first=$(ssh "$SSH_TARGET" "cmp -l -n $received '$RDIR/ref.bin' '$RDIR/rx.bin' | head -1 | awk '{print \$1 - 1}'")
        dump_off=$(( first / 16 * 16 ))
        echo "  received:"
        ssh "$SSH_TARGET" "od -A d -t x1 -j $dump_off -N 80 '$RDIR/rx.bin'" | sed 's/^/    /'
        echo "  expected:"
        ssh "$SSH_TARGET" "od -A d -t x1 -j $dump_off -N 80 '$RDIR/ref.bin'" | sed 's/^/    /'
        ssh "$SSH_TARGET" "cp '$RDIR/rx.bin' '$RDIR/rx_corrupt.bin'"
        KEEP_REMOTE=1
        break
    fi
done

if (( corrupted )); then
    log "result: corruption reproduced"
    exit 1
fi
log "result: no corruption over $RUNS x $SIZE"
