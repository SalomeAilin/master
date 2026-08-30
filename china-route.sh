#!/bin/zsh

set -u

FTTR_GW="192.168.1.1"
DNS_SERVER="192.168.1.100"
ETH_IF="en0"
ETH_IP="192.168.1.100"
WIFI_IF="en1"
CN_LIST="/usr/local/etc/china_ip_list.txt"
EXTRA_LIST="/usr/local/etc/domestic_extra_routes.txt"
DOMAIN_LIST="/usr/local/etc/domestic_domains.conf"
LOG_FILE="/var/log/china-route.log"
LOCK_DIR="/tmp/china-route.lock"
FORCE_REBUILD_FILE="/tmp/china-route-force-rebuild"
HEALTH_CHECK_TARGETS="223.5.5.5 119.29.29.29 124.237.177.164 139.159.241.37 8.134.50.24"
MAX_WAIT_SECONDS=120
SLEEP_SECONDS=5

log() {
  /bin/echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

eth_ready() {
  /sbin/ifconfig "$ETH_IF" inet 2>/dev/null | /usr/bin/grep -q "inet $ETH_IP"
}

gateway_ready() {
  /sbin/route -n get "$FTTR_GW" 2>/dev/null | /usr/bin/grep -q "interface: $ETH_IF"
}

wait_for_network() {
  waited=0
  while [ "$waited" -le "$MAX_WAIT_SECONDS" ]; do
    if eth_ready && gateway_ready; then
      if [ "$waited" -gt 0 ]; then
        log "network became ready after ${waited}s gateway=$FTTR_GW interface=$ETH_IF"
      fi
      return 0
    fi

    /bin/sleep "$SLEEP_SECONDS"
    waited=$((waited + SLEEP_SECONDS))
  done

  log "network not ready after ${MAX_WAIT_SECONDS}s ip=$ETH_IP gateway=$FTTR_GW interface=$ETH_IF"
  return 1
}

if ! /bin/mkdir "$LOCK_DIR" 2>/dev/null; then
  if [ -r "$LOCK_DIR/pid" ]; then
    old_pid="$(/bin/cat "$LOCK_DIR/pid" 2>/dev/null)"
    if [ -n "$old_pid" ] && /bin/kill -0 "$old_pid" 2>/dev/null; then
      exit 0
    fi
  fi

  log "removing stale lock: $LOCK_DIR"
  /bin/rm -rf "$LOCK_DIR"
  if ! /bin/mkdir "$LOCK_DIR" 2>/dev/null; then
    log "failed to acquire lock: $LOCK_DIR"
    exit 1
  fi
fi
/bin/echo "$$" > "$LOCK_DIR/pid"
trap '/bin/rm -rf "$LOCK_DIR" 2>/dev/null' EXIT

if [ ! -r "$CN_LIST" ]; then
  log "missing route list: $CN_LIST"
  exit 1
fi

if ! wait_for_network; then
  exit 0
fi

added=0
failed=0
force_rebuild=0

route_ready() {
  target="$1"
  route_info="$(/sbin/route -n get "$target" 2>/dev/null)"

  /bin/echo "$route_info" | /usr/bin/grep -q "gateway: $FTTR_GW" &&
    /bin/echo "$route_info" | /usr/bin/grep -q "interface: $ETH_IF"
}

ipv4s_for_domain() {
  /usr/bin/dig +time=2 +tries=2 +short A @"$DNS_SERVER" "$1" 2>/dev/null | \
    /usr/bin/awk -F. 'NF == 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {print}' | \
    /usr/bin/sort -u
}

routes_healthy() {
  for target in $HEALTH_CHECK_TARGETS; do
    if ! route_ready "$target"; then
      return 1
    fi
  done

  if [ -r "$EXTRA_LIST" ]; then
    while IFS= read -r cidr; do
      cidr="$(/bin/echo "$cidr" | /usr/bin/sed 's/[[:space:]]*#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$cidr" ] && continue

      target="${cidr%/32}"
      if ! route_ready "$target"; then
        return 1
      fi
    done < "$EXTRA_LIST"
  fi

  if [ -r "$DOMAIN_LIST" ]; then
    while IFS= read -r domain; do
      domain="$(/bin/echo "$domain" | /usr/bin/sed 's/[[:space:]]*#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$domain" ] && continue

      ips_text="$(ipv4s_for_domain "$domain")"
      [ -z "$ips_text" ] && continue

      ips=("${(@f)ips_text}")
      for ip in $ips; do
        if ! route_ready "$ip"; then
          return 1
        fi
      done
    done < "$DOMAIN_LIST"
  fi

  return 0
}

if [ -e "$FORCE_REBUILD_FILE" ]; then
  force_rebuild=1
  /bin/rm -f "$FORCE_REBUILD_FILE" >/dev/null 2>&1 || true
fi

if [ "$force_rebuild" -eq 0 ] && routes_healthy; then
  exit 0
fi

if [ "$force_rebuild" -eq 0 ]; then
  force_rebuild=1
  log "route health check failed; rebuilding domestic routes"
fi

replace_route() {
  route_type="$1"
  route_target="$2"

  if [ "$force_rebuild" -eq 1 ]; then
    /sbin/route -n delete "$route_type" -ifscope "$WIFI_IF" "$route_target" "$FTTR_GW" >/dev/null 2>&1 || true
    /sbin/route -n delete "$route_type" "$route_target" "$FTTR_GW" >/dev/null 2>&1 || true
  fi

  if /sbin/route -n add "$route_type" "$route_target" "$FTTR_GW" -ifp "$ETH_IF" >/dev/null 2>&1; then
    added=$((added + 1))
    return 0
  fi

  if [ "$force_rebuild" -eq 0 ]; then
    return 0
  fi

  failed=$((failed + 1))
  return 1
}

add_routes_from_file() {
  list_file="$1"

  [ -r "$list_file" ] || return 0

  while IFS= read -r cidr; do
    cidr="$(/bin/echo "$cidr" | /usr/bin/sed 's/[[:space:]]*#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$cidr" ] && continue

    if [[ "$cidr" == */32 ]]; then
      target="${cidr%/32}"
      replace_route -host "$target"
    else
      replace_route -net "$cidr"
    fi
  done < "$list_file"
}

add_routes_from_domains() {
  list_file="$1"

  [ -r "$list_file" ] || return 0

  while IFS= read -r domain; do
    domain="$(/bin/echo "$domain" | /usr/bin/sed 's/[[:space:]]*#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$domain" ] && continue

    ips_text="$(ipv4s_for_domain "$domain")"
    [ -z "$ips_text" ] && continue

    ips=("${(@f)ips_text}")
    for ip in $ips; do
      replace_route -host "$ip"
    done
  done < "$list_file"
}

add_routes_from_file "$CN_LIST"
add_routes_from_file "$EXTRA_LIST"
add_routes_from_domains "$DOMAIN_LIST"

if [ "$added" -gt 0 ] || [ "$failed" -gt 0 ] || [ "$force_rebuild" -eq 1 ]; then
  log "completed added=$added failed=$failed force_rebuild=$force_rebuild gateway=$FTTR_GW interface=$ETH_IF"
fi

exit 0
