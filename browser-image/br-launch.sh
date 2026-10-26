#!/bin/bash
# Uruchamia Chromium z parametrami profilu przekazanymi przez zmienne BR_* (ustawia je portal).
set -u

CHROMIUM=/usr/bin/chromium
EXT_DIR=/tmp/fpext
DATA_DIR=/home/neko/.config/chromium

export TZ="${BR_TZ:-UTC}"

# --- rozszerzenie maskujące fingerprint (konfiguracja profilu -> config.js) -------------
rm -rf "$EXT_DIR"; mkdir -p "$EXT_DIR"
cp /opt/fpext/* "$EXT_DIR"/
LOAD="$EXT_DIR"
if [ -n "${BR_FP_B64:-}" ]; then
  printf 'self.__VMBR_FP__=%s;\n' "$(echo "$BR_FP_B64" | base64 -d)" > "$EXT_DIR/config.js"
else
  LOAD=""   # maskowanie wyłączone w profilu
fi

# --- rozszerzenia wgrane przez użytkownika (rozpakowane katalogi w /extensions) ---------
for d in ${BR_EXT_DIRS:-}; do
  case "$d" in /extensions/*) [ -f "$d/manifest.json" ] && LOAD="${LOAD:+$LOAD,}$d" ;; esac
done

# --- polityka sesji: wtyczki ze sklepu Chrome Web Store (force-install) -------------------
if [ -n "${BR_POLICY_B64:-}" ]; then
  echo "$BR_POLICY_B64" | base64 -d > /etc/chromium/policies/managed/session.json 2>/dev/null || true
fi

# --- UA: wersja zgodna z faktycznym Chromium ---------------------------------------------
MAJOR="$($CHROMIUM --version 2>/dev/null | grep -oE '[0-9]+' | head -1)"
UA=""
if [ -n "${BR_UA:-}" ] && [ -n "$MAJOR" ]; then UA="${BR_UA//%MAJOR%/$MAJOR}"; fi

ARGS=(
  --no-sandbox
  --user-data-dir="$DATA_DIR"
  --no-first-run --no-default-browser-check
  --window-position=0,0 --start-maximized
  --remote-debugging-port=9222            # tylko 127.0.0.1 - używa go runner skryptów
  --lang="${BR_LANG:-pl-PL}" --accept-lang="${BR_ACCEPT_LANG:-pl-PL,pl}"
  --force-webrtc-ip-handling-policy=disable_non_proxied_udp
  --password-store=basic
  --disable-dev-shm-usage
  --disable-sync --disable-default-apps --disable-component-update
  --disable-background-networking --disable-breakpad --no-pings
  --disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication
  # --- oszczędność RAM ---
  --enable-low-end-device-mode
  --renderer-process-limit="${BR_RENDERERS:-3}"
  --js-flags="--max-old-space-size=${BR_V8_MB:-512}"
  --disk-cache-dir=/tmp/chromium-cache --disk-cache-size=67108864 --media-cache-size=33554432
)

if [ "${BR_WEBGL:-1}" = "1" ]; then
  ARGS+=(--use-gl=angle --use-angle=swiftshader --enable-unsafe-swiftshader)
else
  ARGS+=(--disable-gpu --disable-software-rasterizer)
fi
[ -n "$UA" ] && ARGS+=(--user-agent="$UA")
[ -n "$LOAD" ] && ARGS+=(--load-extension="$LOAD")
[ -n "${BR_PROXY:-}" ] && ARGS+=(--proxy-server="$BR_PROXY")

exec "$CHROMIUM" "${ARGS[@]}" "${BR_START_URL:-about:blank}"
