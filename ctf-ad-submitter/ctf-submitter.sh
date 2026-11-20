#!/bin/sh
### BEGIN INIT INFO
# Provides:          ctf-submitter
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: CTF A/D exploit runner and flag submitter
### END INIT INFO
#
# SysV init script for machines without systemd (e.g. WSL):
#   sudo cp ctf-submitter.sh /etc/init.d/ctf-submitter
#   sudo chmod +x /etc/init.d/ctf-submitter
#   sudo service ctf-submitter start|stop|restart|reload|status|logs
#
# Settings below can be overridden in /etc/default/ctf-submitter.

DIR="${DIR:-/opt/ctf-ad-submitter}"
CONFIG="${CONFIG:-$DIR/config.py}"
PYTHON="${PYTHON:-/usr/bin/python3}"
RUN_AS="${RUN_AS:-}"                   # empty = root; the user needs docker access
LOG="${LOG:-/tmp/ctf-submitter.log}"
PIDFILE="${PIDFILE:-/tmp/ctf-submitter.pid}"
STOP_TIMEOUT="${STOP_TIMEOUT:-10}"

[ -r /etc/default/ctf-submitter ] && . /etc/default/ctf-submitter

NAME=ctf-submitter

pid() {
    [ -r "$PIDFILE" ] && cat "$PIDFILE"
}

running() {
    p=$(pid) && [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

start() {
    if running; then
        echo "$NAME already running (pid $(pid))"
        return 0
    fi
    touch "$LOG"
    [ -n "$RUN_AS" ] && chown "$RUN_AS" "$LOG"
    rm -f "$PIDFILE"
    start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" \
        --chdir "$DIR" ${RUN_AS:+--chuid "$RUN_AS"} \
        --startas /bin/sh -- -c \
        "PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 exec \"$PYTHON\" -m submitter --config \"$CONFIG\" >> \"$LOG\" 2>&1"
    sleep 1
    if running; then
        echo "$NAME started (pid $(pid)), log: $LOG"
    else
        echo "$NAME failed to start, last log lines:"
        tail -n 20 "$LOG"
        return 1
    fi
}

stop() {
    if ! running; then
        echo "$NAME not running"
        rm -f "$PIDFILE"
        return 0
    fi
    p=$(pid)
    kill -TERM "$p"                    # the submitter kills its running exploits
    i=0
    while kill -0 "$p" 2>/dev/null && [ "$i" -lt "$STOP_TIMEOUT" ]; do
        sleep 1
        i=$((i + 1))
    done
    if kill -0 "$p" 2>/dev/null; then
        echo "$NAME did not stop in ${STOP_TIMEOUT}s, killing"
        kill -KILL "$p"
    fi
    rm -f "$PIDFILE"
    echo "$NAME stopped"
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; start ;;
    reload)
        if running; then
            kill -HUP "$(pid)" && echo "$NAME: reload sent, see the log for the result"
        else
            echo "$NAME not running"; exit 1
        fi ;;
    status)
        if running; then echo "$NAME running (pid $(pid))"; else echo "$NAME stopped"; exit 3; fi ;;
    logs)
        tail -n "${2:-100}" -F "$LOG" ;;
    *)
        echo "usage: $0 {start|stop|restart|reload|status|logs [lines]}"; exit 2 ;;
esac
