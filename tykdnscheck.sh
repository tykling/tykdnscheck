#!/bin/sh
while true; do
    /usr/home/tykdnscheck/tykdnscheck/tykdnscheck.py "$@"
    echo "restarting... (args: $@)"
    sleep 1
done

