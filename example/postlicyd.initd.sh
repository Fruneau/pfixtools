#!/bin/sh

die() {
  echo "$1"
  exit 1
}

POSTLICYD=/usr/sbin/postlicyd
PIDFILE=/var/run/postlicyd/pid
CONF=/etc/pfixtools/postlicyd.conf

[ -z $1 ] && die "usage $0 (start|stop|reload|check-conf)"

mkdir -p `dirname "$PIDFILE"` || die "Can't create $PIDFILE"

do_checkconf() {
  $POSTLICYD -c "$CONF" &> /dev/null
  return "$?"
}

case "$1" in
  start)
    echo "Starting postlicyd..."
    start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $POSTLICYD --text > /dev/null || die "Already running"
    do_checkconf || die "Invalid configuration"
    start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $POSTLICYD -- -p "$PIDFILE" "$CONF" || die "Failed"
    echo "Started"
    ;;

  stop)
    echo "Stopping postlicyd..."
    start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name "postlicyd"
    case "$?" in
      0) echo "Stopped" ;;
      1) die "Nothing to stop" ;;
      2) die "Cannot stop process" ;;
    esac
    ;;

  reload)
    echo "Reloading postlicyd..."
    do_checkconf || die "Invalid configuration"
    start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name postlicyd
    ;;

  check-conf)
    do_checkconf || die "Invalid configuration"
    ;;

  *)
    die "usage $0 (start|stop|reload|check-conf)"
    ;;
esac
