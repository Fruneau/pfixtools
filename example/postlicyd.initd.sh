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
    $POSTLICYD -p "$PIDFILE" "$CONF"
    ;;

  stop)
    kill `cat $PIDFILE`
    ;;

  reload)
    kill -HUP `cat $PIDFILE`
    ;;

  *)
    die "usage $0 (start|stop|reload)"
    ;;
esac
