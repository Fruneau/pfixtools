#!/bin/sh

die() {
  echo "$1"
  exit 1
}

POSTLICYD=/usr/sbin/postlicyd
PIDFILE=/var/run/postlicyd/pid
CONF=/etc/pfixtools/postlicyd.conf

[ -z $1 ] && die "usage $0 (start|stop|reload)"

case "$1" in
  start)
    mkdir -p `dirname "$PIDFILE"` || die "Can't create $PIDFILE"
    echo "Starting postlicyd..."
    flock -x -n "$PIDFILE" -c "true" || die "Already started"
    $POSTLICYD -p "$PIDFILE" "$CONF" || die "Failed"
    echo "Started"
    ;;

  stop)
    echo "Stopping postlicyd..."
    ( flock -x -n "$PIDFILE" -c "true" && die "Not started" ) \
      || ( kill `cat $PIDFILE` && echo "Stopped" ) \
      || die "Failed"
    ;;

  reload)
    echo "Reloading postlicyd..."
    ( flock -x -n "$PIDFILE" -c "true" && die "Not started" ) \
      || ( kill -HUP `cat $PIDFILE` && ( sleep 3; echo "Done" ) ) \
      || die "Failed"
    ;;

  *)
    die "usage $0 (start|stop|reload)"
    ;;
esac
