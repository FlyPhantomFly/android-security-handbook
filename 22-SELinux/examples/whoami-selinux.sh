#!/usr/bin/env bash
# examples/whoami-selinux.sh — run on the device, or via adb shell
#
# Prints the calling process's SELinux context and decodes the MCS categories.
# Works from adb shell, from a terminal app, or from inside `run-as`.

CTX=$(cat /proc/self/attr/current | tr -d '\0')
echo "context : $CTX"

TYPE=$(echo "$CTX" | cut -d: -f3)
LEVEL=$(echo "$CTX" | cut -d: -f4-)
echo "domain  : $TYPE"
echo "level   : ${LEVEL:-none}"

MYUID=$(id -u)
USERID=$(( MYUID / 100000 ))
RAW=$(( MYUID % 100000 ))
if   [ "$RAW" -ge 90000 ]; then APPID=$(( RAW - 90000 ))
elif [ "$RAW" -ge 20000 ]; then APPID=$(( RAW - 20000 ))
elif [ "$RAW" -ge 10000 ]; then APPID=$(( RAW - 10000 ))
else APPID=$RAW
fi

echo "uid     : $MYUID  ->  android user $USERID, appid $APPID"
echo "predicted levelFrom=all : s0:c$(( APPID & 255 )),c$(( 256 + (APPID >> 8) )),c$(( 512 + (USERID & 255) )),c$(( 768 + (USERID >> 8) ))"
