#!/bin/zsh

set -u

DNS_SERVER="192.168.1.100"
WIFI_SERVICE="Wi-Fi"
ETH_SERVICE="Ethernet"
WIFI_GW="172.20.10.1"
WIFI_IF="en1"
ETH_GW="192.168.1.1"
ETH_IF="en0"
ETH_IP="192.168.1.100"
FOREIGN_BLOCK_GW="127.0.0.1"
FOREIGN_BLOCK_LOW_SAMPLE="8.8.8.8"
FOREIGN_BLOCK_HIGH_SAMPLE="208.67.222.222"
DNSMASQ_LABEL="homebrew.mxcl.dnsmasq"
DNSMASQ_BIN="/usr/local/sbin/dnsmasq-network-split"
DNSMASQ_CONFIG="/usr/local/etc/dnsmasq-network-split.conf"
DNSMASQ_CELLAR_DIR="/opt/homebrew/Cellar/dnsmasq"
CHINA_ROUTE_LABEL="com.local.china-route"
EXTRA_ROUTE_LIST="/usr/local/etc/domestic_extra_routes.txt"
DOMESTIC_DOMAIN_LIST="/usr/local/etc/domestic_domains.conf"
FORCE_REBUILD_FILE="/tmp/china-route-force-rebuild"
LOG_FILE="/var/log/network-split-guard.log"
MAX_WAIT_SECONDS=60
SLEEP_SECONDS=3
KICKSTART_TIMEOUT_SECONDS=8

log() {
  /bin/echo "$(/bin/date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

service_exists() {
  /usr/sbin/networksetup -listallnetworkservices 2>/dev/null | /usr/bin/grep -Fxq "$1"
}

ensure_dns() {
  service="$1"

  if ! service_exists "$service"; then
    return 0
  fi

  current="$(/usr/sbin/networksetup -getdnsservers "$service" 2>/dev/null | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/[[:space:]]*$//')"
  if [ "$current" != "$DNS_SERVER" ]; then
    if /usr/sbin/networksetup -setdnsservers "$service" "$DNS_SERVER" >/dev/null 2>&1; then
      log "fixed dns service=$service from='$current' to=$DNS_SERVER"
    else
      log "failed to fix dns service=$service current='$current'"
    fi
  fi
}

ensure_dnsmasq_binary() {
  if [ -x "$DNSMASQ_BIN" ]; then
    return 0
  fi

  candidate=""
  for path in "$DNSMASQ_CELLAR_DIR"/*/sbin/dnsmasq(N); do
    candidate="$path"
  done

  if [ -z "$candidate" ]; then
    log "dnsmasq binary missing path=$DNSMASQ_BIN cellar=$DNSMASQ_CELLAR_DIR"
    return 1
  fi

  if /usr/bin/install -o root -g wheel -m 555 "$candidate" "$DNSMASQ_BIN" >/dev/null 2>&1 && [ -x "$DNSMASQ_BIN" ]; then
    log "restored fixed dnsmasq binary source=$candidate target=$DNSMASQ_BIN"
    return 0
  fi

  log "failed to restore fixed dnsmasq binary source=$candidate target=$DNSMASQ_BIN"
  return 1
}

dnsmasq_config_ok() {
  ensure_dnsmasq_binary || return 1

  config_output="$("$DNSMASQ_BIN" --test --conf-file="$DNSMASQ_CONFIG" 2>&1)"
  config_status=$?
  if [ "$config_status" -eq 0 ]; then
    return 0
  fi

  log "dnsmasq config test failed status=$config_status error='$(route_error_text "$config_output")'"
  return 1
}

dnsmasq_running() {
  /bin/ps -axo command | /usr/bin/grep -F "$DNSMASQ_BIN" | /usr/bin/grep -v grep >/dev/null 2>&1
}

kickstart_system_service() {
  mode="$1"
  label="$2"

  (
    if [ "$mode" = "restart" ]; then
      /bin/launchctl kickstart -k "system/$label" >/dev/null 2>&1
    else
      /bin/launchctl kickstart "system/$label" >/dev/null 2>&1
    fi
  ) &
  kick_pid=$!
  waited=0

  while /bin/kill -0 "$kick_pid" >/dev/null 2>&1; do
    if [ "$waited" -ge "$KICKSTART_TIMEOUT_SECONDS" ]; then
      /bin/kill -TERM "$kick_pid" >/dev/null 2>&1 || true
      /bin/sleep 1
      /bin/kill -KILL "$kick_pid" >/dev/null 2>&1 || true
      log "launchctl kickstart timeout label=$label mode=$mode after=${KICKSTART_TIMEOUT_SECONDS}s"
      return 1
    fi

    /bin/sleep 1
    waited=$((waited + 1))
  done

  /bin/wait "$kick_pid" >/dev/null 2>&1
  return 0
}

ensure_dnsmasq() {
  if dnsmasq_running; then
    return 0
  fi

  dnsmasq_config_ok || return 1

  log "dnsmasq not running; restarting"
  kickstart_system_service restart "$DNSMASQ_LABEL" || true
}

ensure_dns_responds() {
  attempt=0

  while [ "$attempt" -lt 3 ]; do
    if [ -n "$(first_ipv4 baidu.com)" ] && [ -n "$(first_ipv4 google.com)" ]; then
      return 0
    fi

    attempt=$((attempt + 1))
    if [ "$attempt" -eq 1 ]; then
      log "dnsmasq not responding; restarting"
      dnsmasq_config_ok && kickstart_system_service restart "$DNSMASQ_LABEL" || true
    fi

    /bin/sleep 2
  done

  log "dnsmasq still not responding after retries"
  return 1
}

first_ipv4() {
  /usr/bin/dig +time=2 +tries=2 +short A @"$DNS_SERVER" "$1" 2>/dev/null | \
    /usr/bin/awk -F. 'NF == 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {print; exit}'
}

ipv4s_for_domain() {
  /usr/bin/dig +time=2 +tries=2 +short A @"$DNS_SERVER" "$1" 2>/dev/null | \
    /usr/bin/awk -F. 'NF == 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {print}' | \
    /usr/bin/sort -u
}

check_route() {
  target="$1"
  expected_gateway="$2"
  expected_iface="$3"

  iface="$(/sbin/route -n get "$target" 2>/dev/null | /usr/bin/awk '/interface:/{print $2; exit}')"
  gateway="$(/sbin/route -n get "$target" 2>/dev/null | /usr/bin/awk '/gateway:/{print $2; exit}')"

  if [ "$iface" != "$expected_iface" ] || [ "$gateway" != "$expected_gateway" ]; then
    log "route drift target=$target gateway=$gateway interface=$iface expected_gateway=$expected_gateway expected_interface=$expected_iface"
    return 1
  fi

  return 0
}

dhcp_wifi_gateway() {
  /usr/sbin/ipconfig getpacket "$WIFI_IF" 2>/dev/null | /usr/bin/awk -F'[{}]' '
    /router \(ip_mult\):/ {
      split($2, values, /[,[:space:]]+/)
      for (i in values) {
        if (values[i] ~ /^[0-9]+(\.[0-9]+){3}$/) {
          print values[i]
          exit
        }
      }
    }
  '
}

route_gateway_on_wifi() {
  gateway="$1"
  [ -n "$gateway" ] || return 1

  /sbin/route -n get "$gateway" 2>/dev/null | /usr/bin/grep -q "interface: $WIFI_IF"
}

active_wifi_gateway() {
  gateway="$(dhcp_wifi_gateway)"
  if route_gateway_on_wifi "$gateway"; then
    /bin/echo "$gateway"
    return 0
  fi

  if route_gateway_on_wifi "$WIFI_GW"; then
    /bin/echo "$WIFI_GW"
    return 0
  fi

  route_info="$(read_default_route)"
  gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"
  if [ "$iface" = "$WIFI_IF" ] && route_gateway_on_wifi "$gateway"; then
    /bin/echo "$gateway"
    return 0
  fi

  return 1
}

wifi_route_label() {
  gateway="$(active_wifi_gateway 2>/dev/null || true)"
  /bin/echo "${gateway:-$WIFI_GW}/${WIFI_IF}"
}

foreign_default_route_active() {
  route_info="$(read_default_route)"
  gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"

  [ "$iface" = "$WIFI_IF" ] && route_gateway_on_wifi "$gateway"
}

add_domestic_host_route() {
  domain="$1"
  ip="$2"

  before="$(/sbin/route -n get "$ip" 2>/dev/null | /usr/bin/awk '
    /gateway:/{gateway=$2}
    /interface:/{iface=$2}
    END{print gateway "/" iface}
  ')"

  /sbin/route -n delete -host -ifscope "$WIFI_IF" "$ip" "$WIFI_GW" >/dev/null 2>&1 || true
  /sbin/route -n delete -host "$ip" "$WIFI_GW" >/dev/null 2>&1 || true
  /sbin/route -n delete -host "$ip" >/dev/null 2>&1 || true

  add_error="$(/sbin/route -n add -host "$ip" "$ETH_GW" -ifp "$ETH_IF" 2>&1 >/dev/null)"

  if check_route "$ip" "$ETH_GW" "$ETH_IF"; then
    log "bound domestic domain host route domain=$domain ip=$ip from=${before:-unknown} to=${ETH_GW}/${ETH_IF} add_error='$(route_error_text "$add_error")'"
    return 0
  fi

  log "failed to bind domestic domain host route domain=$domain ip=$ip from=${before:-unknown} expected=${ETH_GW}/${ETH_IF} add_error='$(route_error_text "$add_error")'"
  return 1
}

check_extra_routes() {
  [ -r "$EXTRA_ROUTE_LIST" ] || return 0

  while IFS= read -r cidr; do
    cidr="$(/bin/echo "$cidr" | /usr/bin/sed 's/[[:space:]]*#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$cidr" ] && continue

    target="${cidr%/32}"
    if ! check_route "$target" "$ETH_GW" "$ETH_IF"; then
      log "extra route drift target=$target list=$EXTRA_ROUTE_LIST"
      return 1
    fi
  done < "$EXTRA_ROUTE_LIST"

  return 0
}

check_domestic_domain() {
  domain="$1"
  ips_text="$(ipv4s_for_domain "$domain")"

  if [ -z "$ips_text" ]; then
    log "failed to resolve domestic domain=$domain via_dns=$DNS_SERVER"
    return 1
  fi

  ips=("${(@f)ips_text}")
  for ip in $ips; do
    if ! check_route "$ip" "$ETH_GW" "$ETH_IF"; then
      log "domestic domain route drift domain=$domain ip=$ip"
      add_domestic_host_route "$domain" "$ip" || return 1
    fi
  done

  return 0
}

check_domestic_domains() {
  if [ ! -r "$DOMESTIC_DOMAIN_LIST" ]; then
    for domain in baidu.com bilibili.com console.volcengine.com alsay.net pan.baidu.com yun.baidu.com pcs.baidu.com d.pcs.baidu.com baidupcs.com qd.baidupcs.com bj.baidupcs.com; do
      check_domestic_domain "$domain" || return 1
    done
    return 0
  fi

  while IFS= read -r domain; do
    domain="$(/bin/echo "$domain" | /usr/bin/sed 's/[[:space:]]*#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$domain" ] && continue

    check_domestic_domain "$domain" || return 1
  done < "$DOMESTIC_DOMAIN_LIST"

  return 0
}

china_route_running() {
  /bin/launchctl print "system/$CHINA_ROUTE_LABEL" 2>/dev/null | /usr/bin/grep -q "state = running"
}

protect_foreign_priority() {
  if ! wifi_gateway_ready; then
    return 0
  fi

  if foreign_default_route_active; then
    return 0
  fi

  if ensure_foreign_default_route quiet >/dev/null 2>&1; then
    return 0
  fi

  log "foreign priority protection failed; default route is not $(wifi_route_label)"
  return 1
}

ensure_china_routes() {
  bad=0

  for ip in 223.5.5.5 119.29.29.29 124.237.177.164 139.159.241.37 163.181.253.200 8.134.50.24; do
    if ! check_route "$ip" "$ETH_GW" "$ETH_IF"; then
      bad=1
      break
    fi
  done

  if [ "$bad" -eq 0 ] && ! check_extra_routes; then
    bad=1
  fi

  if ! check_domestic_domains; then
    bad=1
  fi

  if [ "$bad" -eq 1 ]; then
    if ! protect_foreign_priority; then
      log "skipping domestic route rebuild to preserve foreign priority"
      return 0
    fi

    /usr/bin/touch "$FORCE_REBUILD_FILE" >/dev/null 2>&1 || true
    if china_route_running; then
      log "domestic routes still rebuilding; waiting for $CHINA_ROUTE_LABEL to finish"
      return 0
    fi
    kickstart_system_service start "$CHINA_ROUTE_LABEL" || true
    protect_foreign_priority >/dev/null 2>&1 || true
  fi
}

read_default_route() {
  /sbin/route -n get default 2>/dev/null | /usr/bin/awk '
    /gateway:/{gateway=$2}
    /interface:/{iface=$2}
    END{print gateway, iface}
  '
}

default_route_matches() {
  expected_gateway="$1"
  expected_iface="$2"

  route_info="$(read_default_route)"
  actual_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  actual_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"

  [ "$actual_gateway" = "$expected_gateway" ] && [ "$actual_iface" = "$expected_iface" ]
}

log_if_not_quiet() {
  mode="$1"
  shift

  if [ "$mode" != "quiet" ]; then
    log "$@"
  fi
}

route_error_text() {
  /bin/echo "$1" | /usr/bin/tr '\n' ' ' | /usr/bin/sed "s/'//g;s/[[:space:]][[:space:]]*/ /g;s/[[:space:]]*$//"
}

rebuild_default_route() {
  target_gateway="$1"
  target_iface="$2"
  reason="$3"
  current_gateway="${4:-}"

  change_error="$(/sbin/route -n change default "$target_gateway" -ifp "$target_iface" 2>&1 >/dev/null)"
  if default_route_matches "$target_gateway" "$target_iface"; then
    return 0
  fi

  seen_gateways=""
  for gateway in "$current_gateway" "$WIFI_GW" "$ETH_GW"; do
    [ -n "$gateway" ] || continue
    case " $seen_gateways " in
      *" $gateway "*) continue ;;
    esac
    seen_gateways="$seen_gateways $gateway"
    /sbin/route -n delete default "$gateway" >/dev/null 2>&1 || true
  done
  /sbin/route -n delete default >/dev/null 2>&1 || true

  add_error="$(/sbin/route -n add default "$target_gateway" -ifp "$target_iface" 2>&1 >/dev/null)"
  if default_route_matches "$target_gateway" "$target_iface"; then
    log "rebuilt default route reason=$reason to=${target_gateway}/${target_iface} previous_gateway=${current_gateway:-none} change_error='$(route_error_text "$change_error")' add_error='$(route_error_text "$add_error")'"
    return 0
  fi

  route_info="$(read_default_route)"
  actual_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  actual_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"
  log "failed to rebuild default route reason=$reason to=${target_gateway}/${target_iface} actual=${actual_gateway}/${actual_iface} change_error='$(route_error_text "$change_error")' add_error='$(route_error_text "$add_error")'"
  return 1
}

default_route_ok() {
  gateway="$1"
  iface="$2"

  if [ "$iface" = "$WIFI_IF" ] && route_gateway_on_wifi "$gateway"; then
    return 0
  fi

  if wired_default_active "$gateway" "$iface" &&
    ! wifi_gateway_ready &&
    foreign_block_routes_active; then
    return 0
  fi

  return 1
}

wired_default_active() {
  gateway="$1"
  iface="$2"

  [ "$gateway" = "$ETH_GW" ] && [ "$iface" = "$ETH_IF" ]
}

ethernet_gateway_ready() {
  /sbin/ifconfig "$ETH_IF" inet 2>/dev/null | /usr/bin/grep -q "inet $ETH_IP" &&
    /sbin/route -n get "$ETH_GW" 2>/dev/null | /usr/bin/grep -q "interface: $ETH_IF"
}

foreign_block_route_active() {
  target="$1"

  /sbin/route -n get "$target" 2>/dev/null | /usr/bin/awk -v gateway="$FOREIGN_BLOCK_GW" '
    /gateway:/{actual_gateway=$2}
    /interface:/{iface=$2}
    /flags:/ && /REJECT/{reject=1}
    END{exit !(actual_gateway == gateway && iface == "lo0" && reject == 1)}
  '
}

foreign_block_routes_active() {
  foreign_block_route_active "$FOREIGN_BLOCK_LOW_SAMPLE" &&
    foreign_block_route_active "$FOREIGN_BLOCK_HIGH_SAMPLE"
}

ensure_foreign_block_routes() {
  if foreign_block_routes_active; then
    return 0
  fi

  low_error="$(/sbin/route -n add -net 0.0.0.0/1 "$FOREIGN_BLOCK_GW" -reject 2>&1 >/dev/null)"
  high_error="$(/sbin/route -n add -net 128.0.0.0/1 "$FOREIGN_BLOCK_GW" -reject 2>&1 >/dev/null)"

  if foreign_block_routes_active; then
    log "blocked foreign fallback while wifi is unavailable routes=0.0.0.0/1,128.0.0.0/1 gateway=${FOREIGN_BLOCK_GW}/lo0"
    return 0
  fi

  log "failed to block foreign fallback low_error='$(route_error_text "$low_error")' high_error='$(route_error_text "$high_error")'"
  return 1
}

remove_foreign_block_routes() {
  low_active=0
  high_active=0
  foreign_block_route_active "$FOREIGN_BLOCK_LOW_SAMPLE" && low_active=1
  foreign_block_route_active "$FOREIGN_BLOCK_HIGH_SAMPLE" && high_active=1

  if [ "$low_active" -eq 0 ] && [ "$high_active" -eq 0 ]; then
    return 0
  fi

  [ "$low_active" -eq 1 ] &&
    /sbin/route -n delete -net 0.0.0.0/1 "$FOREIGN_BLOCK_GW" >/dev/null 2>&1 || true
  [ "$high_active" -eq 1 ] &&
    /sbin/route -n delete -net 128.0.0.0/1 "$FOREIGN_BLOCK_GW" >/dev/null 2>&1 || true

  if foreign_block_routes_active; then
    log "failed to remove foreign fallback block after wifi recovered"
    return 1
  fi

  log "removed foreign fallback block after wifi recovered"
  return 0
}

ensure_wired_fallback_route() {
  route_info="$(read_default_route)"
  default_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  default_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"

  if wired_default_active "$default_gateway" "$default_iface"; then
    return 0
  fi

  if ! ethernet_gateway_ready; then
    log "wired fallback unavailable default_gateway=$default_gateway default_interface=$default_iface expected_fallback=${ETH_GW}/${ETH_IF}"
    return 1
  fi

  rebuild_default_route "$ETH_GW" "$ETH_IF" "wired_fallback" "$default_gateway" || true

  if default_route_matches "$ETH_GW" "$ETH_IF"; then
    log "using wired route for domestic access while wifi is unavailable from=${default_gateway}/${default_iface} to=${ETH_GW}/${ETH_IF}"
    return 0
  fi

  route_info="$(read_default_route)"
  actual_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  actual_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"
  log "failed to set wired route for domestic access from=${default_gateway}/${default_iface} to=${ETH_GW}/${ETH_IF} actual=${actual_gateway}/${actual_iface}"
  return 1
}

wifi_gateway_ready() {
  /sbin/ifconfig "$WIFI_IF" inet 2>/dev/null | /usr/bin/grep -q "inet " &&
    active_wifi_gateway >/dev/null 2>&1
}

ensure_foreign_default_route() {
  log_unavailable="${1:-log}"
  route_info="$(read_default_route)"
  default_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  default_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"

  if ! wifi_gateway_ready; then
    ensure_wired_fallback_route >/dev/null 2>&1 || true
    ensure_foreign_block_routes >/dev/null 2>&1 || true
    log_if_not_quiet "$log_unavailable" "wifi unavailable; foreign fallback blocked while domestic sites use wired default_gateway=$default_gateway default_interface=$default_iface wired=${ETH_GW}/${ETH_IF}"
    return 1
  fi

  if ! remove_foreign_block_routes; then
    log_if_not_quiet "$log_unavailable" "wifi available but foreign fallback block could not be removed"
    return 1
  fi

  if default_route_ok "$default_gateway" "$default_iface"; then
    return 0
  fi

  target_wifi_gateway="$(active_wifi_gateway 2>/dev/null || true)"
  if [ -z "$target_wifi_gateway" ]; then
    ensure_wired_fallback_route >/dev/null 2>&1 || true
    ensure_foreign_block_routes >/dev/null 2>&1 || true
    log_if_not_quiet "$log_unavailable" "wifi gateway not discoverable; foreign fallback blocked while domestic sites use wired default_gateway=$default_gateway default_interface=$default_iface wired=${ETH_GW}/${ETH_IF}"
    return 1
  fi

  rebuild_default_route "$target_wifi_gateway" "$WIFI_IF" "wifi_foreign" "$default_gateway" || true

  if default_route_matches "$target_wifi_gateway" "$WIFI_IF"; then
    log_if_not_quiet "$log_unavailable" "restored wifi route for foreign sites from=${default_gateway}/${default_iface} to=${target_wifi_gateway}/${WIFI_IF}"
    return 0
  fi

  route_info="$(read_default_route)"
  actual_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  actual_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"
  log_if_not_quiet "$log_unavailable" "failed to restore wifi route for foreign sites from=${default_gateway}/${default_iface} to=${target_wifi_gateway}/${WIFI_IF} actual=${actual_gateway}/${actual_iface}"
  return 1
}

network_ready() {
  route_info="$(read_default_route)"
  default_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  default_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"

  if ! default_route_ok "$default_gateway" "$default_iface"; then
    return 1
  fi

  if ! /sbin/ifconfig "$ETH_IF" inet 2>/dev/null | /usr/bin/grep -q "inet $ETH_IP"; then
    return 1
  fi

  if ! /sbin/route -n get "$ETH_GW" 2>/dev/null | /usr/bin/grep -q "interface: $ETH_IF"; then
    return 1
  fi

  return 0
}

wait_for_network_ready() {
  waited=0

  while [ "$waited" -le "$MAX_WAIT_SECONDS" ]; do
    ensure_foreign_default_route quiet >/dev/null 2>&1 || true

    if network_ready; then
      if [ "$waited" -gt 0 ]; then
        log "network became ready after ${waited}s"
      fi
      return 0
    fi

    /bin/sleep "$SLEEP_SECONDS"
    waited=$((waited + SLEEP_SECONDS))
  done

  route_info="$(read_default_route)"
  default_gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
  default_iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"
  log "network not ready after ${MAX_WAIT_SECONDS}s default_gateway=$default_gateway default_interface=$default_iface expected_default=$(wifi_route_label)"
  return 1
}

log_default_route() {
  attempt=0
  gateway=""
  iface=""

  while [ "$attempt" -lt 3 ]; do
    route_info="$(read_default_route)"
    gateway="$(/bin/echo "$route_info" | /usr/bin/awk '{print $1}')"
    iface="$(/bin/echo "$route_info" | /usr/bin/awk '{print $2}')"

    if default_route_ok "$gateway" "$iface"; then
      return 0
    fi

    attempt=$((attempt + 1))
    if [ "$attempt" -lt 3 ]; then
      /bin/sleep 2
    fi
  done

  if [ -z "$gateway" ] && [ -z "$iface" ]; then
    log "default route unavailable after retries"
  else
    log "default route drift gateway=$gateway interface=$iface expected_default=${WIFI_GW}/${WIFI_IF}"
  fi
}

ensure_dns "$WIFI_SERVICE"
ensure_dns "$ETH_SERVICE"
ensure_dnsmasq
ensure_foreign_default_route

if ! wait_for_network_ready; then
  exit 0
fi

if ! ensure_dns_responds; then
  exit 0
fi

ensure_china_routes
protect_foreign_priority >/dev/null 2>&1 || true
log_default_route

exit 0
