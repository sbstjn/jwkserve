#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  set -- serve
elif [ "${1#-}" != "$1" ]; then
  set -- serve "$@"
fi

if [ "$1" = "serve" ]; then
  has_port=0
  has_bind=0

  for arg in "$@"; do
    case "$arg" in
      -p|--port|--port=*) has_port=1 ;;
      -b|--bind|--bind=*) has_bind=1 ;;
    esac
  done

  if [ "$has_port" -eq 0 ]; then
    set -- "$@" --port 3000
  fi

  if [ "$has_bind" -eq 0 ]; then
    set -- "$@" --bind 0.0.0.0
  fi
fi

exec /usr/local/bin/jwkserve "$@"
