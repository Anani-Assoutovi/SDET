#!/bin/bash

WIFI_IFACE=$(networksetup -listallhardwareports \
  | awk '/Wi-Fi|AirPort/{getline; print $2}')

[[ -z "$WIFI_IFACE" ]] && echo '{"error":"Wi-Fi interface not found"}' && exit 1

echo '{'
echo '  "interface": "'"$WIFI_IFACE"'",'
echo '  "networks": ['

FIRST=true

networksetup -listpreferredwirelessnetworks "$WIFI_IFACE" \
  | tail -n +2 \
  | sed 's/^[[:space:]]*//' \
  | while IFS= read -r SSID; do

    RAW=$(security find-generic-password -ga "$SSID" 2>&1)
    PASSWORD=$(echo "$RAW" | sed -n 's/^password: "\(.*\)"/\1/p')

    [[ -z "$PASSWORD" ]] && PASSWORD=null || PASSWORD="\"$PASSWORD\""

    $FIRST || echo ','
    FIRST=false

    echo '    {'
    echo '      "ssid": "'"$SSID"'",'
    echo '      "password": '"$PASSWORD"
    echo -n '    }'
done

echo
echo '  ]'
echo '}'
