#!/usr/bin/env bash
# NodeLite Auto Deploy - one-click installer for the web app itself.
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/dabao9037/nodelite-auto-deploy/main/install.sh)
#        bash install.sh [install|update|uninstall|password|status]
set -Eeuo pipefail

REPO="${NLAD_REPO:-dabao9037/nodelite-auto-deploy}"
REF="${NLAD_REF:-main}"
APP="nodelite-auto-deploy"
ROOT="/opt/$APP"
CURRENT="$ROOT/current"
VENV="$ROOT/venv"
ENV_FILE="/etc/$APP.env"
UNIT="/etc/systemd/system/$APP.service"
BIN="/usr/local/bin/nladmin"
SVC_USER="nlad"
DATA_DIR="/var/lib/$APP"
umask 022

info() { printf '\033[0;36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
random_password() { python3 -c 'import secrets;print(secrets.token_urlsafe(18))'; }
random_secret() { python3 -c 'import secrets;print(secrets.token_urlsafe(48))'; }
read_key() { if [[ -f "$ENV_FILE" ]]; then sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; fi; }
set_key() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$ENV_FILE" >"$tmp" || true
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  install -o root -g root -m 0600 "$tmp" "$ENV_FILE"
  rm -f "$tmp"
}

require_root() { [[ $EUID -eq 0 ]] || die "请使用 root 运行：sudo bash install.sh"; }
require_systemd() { if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then die "需要 systemd"; fi; }

ensure_deps() {
  local missing=0 cmd
  for cmd in python3 curl tar; do command -v "$cmd" >/dev/null 2>&1 || missing=1; done
  python3 -c 'import ensurepip, venv' >/dev/null 2>&1 || missing=1
  if (( missing == 1 )); then
    info "安装依赖：python3 python3-venv curl tar"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv curl ca-certificates tar >/dev/null
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q python3 curl ca-certificates tar
    elif command -v yum >/dev/null 2>&1; then yum install -y -q python3 curl ca-certificates tar
    else die "仅支持 apt/dnf/yum 系统，请先手动安装 python3、python3-venv、curl"; fi
  fi
  need python3; need curl; need tar
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "需要 Python 3.10 及以上"
}

fetch_release() {
  local destination="$1" tarball
  mkdir -p "$destination"
  if [[ -n "${NLAD_SOURCE_DIR:-}" ]]; then
    # Local source (used for testing before publishing).
    cp -a "$NLAD_SOURCE_DIR/." "$destination/"
    rm -rf "$destination/.git" "$destination/.deps" "$destination/.venv"
  else
    tarball="$(mktemp)"
    info "下载 $REPO@$REF"
    curl -fsSL --retry 3 --connect-timeout 15 "https://codeload.github.com/$REPO/tar.gz/$REF" -o "$tarball"
    tar -xzf "$tarball" -C "$destination" --strip-components=1
    rm -f "$tarball"
  fi
  [[ -f "$destination/app/main.py" && -f "$destination/requirements.txt" && -f "$destination/$APP.service" ]] \
    || die "下载内容不完整"
  bash -n "$destination/install.sh" || die "安装脚本语法检查失败"
}

write_env() {
  local user="${WEB_ADMIN_USER:-admin}" password="${WEB_ADMIN_PASSWORD:-}" listen="${WEB_LISTEN_HOST:-127.0.0.1}"
  local port="${WEB_LISTEN_PORT:-8780}" public=0
  [[ "$user" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || die "WEB_ADMIN_USER 格式错误"
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then die "WEB_LISTEN_PORT 必须在 1-65535"; fi
  [[ "$listen" =~ ^[0-9A-Fa-f.:]+$ ]] || die "WEB_LISTEN_HOST 必须是 IP 地址"
  if [[ "$listen" != 127.* && "$listen" != "::1" ]]; then
    public=1
    warn "你选择了非回环监听地址 $listen。本程序会接收服务器 root 密码，"
    warn "公网明文 HTTP 会让密码在网络上可被窃听。强烈建议保持 127.0.0.1 并用 SSH 隧道或 HTTPS 反代访问。"
    [[ "${WEB_ALLOW_PUBLIC_LISTEN:-0}" == 1 ]] || die "如确认要公网监听，请同时设置 WEB_ALLOW_PUBLIC_LISTEN=1"
  fi
  [[ -n "$password" ]] || password="$(random_password)"
  [[ ${#password} -ge 14 ]] || die "管理员密码至少 14 位"
  (umask 077; cat >"$ENV_FILE") <<EOF
WEB_ADMIN_USER=$user
WEB_ADMIN_PASSWORD=$password
WEB_SESSION_SECRET=$(random_secret)
WEB_COOKIE_SECURE=${WEB_COOKIE_SECURE:-0}
WEB_LISTEN_HOST=$listen
WEB_LISTEN_PORT=$port
WEB_ALLOW_PUBLIC_LISTEN=$public
MAX_CONCURRENT_TASKS=${MAX_CONCURRENT_TASKS:-2}
TASK_RESULT_TTL_SECONDS=${TASK_RESULT_TTL_SECONDS:-900}
ALLOW_PRIVATE_TARGETS=${ALLOW_PRIVATE_TARGETS:-0}
TARGET_ALLOWLIST_CIDRS=${TARGET_ALLOWLIST_CIDRS:-}
WEB_DATA_DIR=$DATA_DIR
EOF
  chown root:root "$ENV_FILE"; chmod 0600 "$ENV_FILE"
  NLAD_SHOW_USER="$user"; NLAD_SHOW_PASSWORD="$password"
}

ensure_data_dir() {
  # 服务器记录 data.db 和加密密钥 secret.key：只有服务用户可读写
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$DATA_DIR"
  chown "$SVC_USER:$SVC_USER" "$DATA_DIR"; chmod 0700 "$DATA_DIR"
  local file
  for file in "$DATA_DIR/data.db" "$DATA_DIR/secret.key"; do
    if [[ -f "$file" ]]; then chown "$SVC_USER:$SVC_USER" "$file"; chmod 0600 "$file"; fi
  done
}

write_cli() {
  install -o root -g root -m 0755 "$CURRENT/nladmin" "$BIN"
}

activate_release() {
  local release="$1" previous=""
  [[ -L "$CURRENT" ]] && previous="$(readlink -f "$CURRENT")"
  rm -rf "$VENV.new"
  python3 -m venv "$VENV.new"
  "$VENV.new/bin/pip" install -q --disable-pip-version-check --no-cache-dir -r "$release/requirements.txt"
  chown -R root:"$SVC_USER" "$release"; chmod -R go-w "$release"; chmod 0750 "$release"
  ln -sfn "$release" "$CURRENT.new"; mv -Tf "$CURRENT.new" "$CURRENT"
  rm -rf "$VENV.old"; if [[ -d "$VENV" ]]; then mv "$VENV" "$VENV.old"; fi; mv "$VENV.new" "$VENV"
  ensure_data_dir
  install -o root -g root -m 0644 "$release/$APP.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable "$APP.service" >/dev/null 2>&1
  systemctl restart "$APP.service"
  if ! wait_healthy; then
    warn "新版本启动失败，最近日志："
    journalctl -u "$APP.service" --no-pager -n 30 >&2 || true
    if [[ -n "$previous" && -d "$VENV.old" ]]; then
      ln -sfn "$previous" "$CURRENT"; rm -rf "$VENV"; mv "$VENV.old" "$VENV"
      systemctl restart "$APP.service" || true
      die "启动失败，已回滚到上一版本"
    fi
    die "启动失败"
  fi
  rm -rf "$VENV.old"
}

wait_healthy() {
  local host port i
  host="$(read_key WEB_LISTEN_HOST)"; port="$(read_key WEB_LISTEN_PORT)"
  [[ "$host" == 0.0.0.0 ]] && host=127.0.0.1
  [[ "$host" == "::" ]] && host="::1"
  [[ "$host" == *:* ]] && host="[$host]"
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://$host:$port/healthz" >/dev/null 2>&1; then return 0; fi
    (( i % 10 != 0 )) || info "等待服务启动（${i} 秒）"
    sleep 1
  done
  return 1
}

print_access() {
  local host port
  host="$(read_key WEB_LISTEN_HOST)"; port="$(read_key WEB_LISTEN_PORT)"
  printf '\n'
  if [[ "$host" == 127.* || "$host" == "::1" ]]; then
    ok "服务仅监听本机 $host:$port。请在你自己的电脑上执行 SSH 隧道："
    printf '\n    ssh -N -L %s:127.0.0.1:%s root@<这台服务器IP>\n\n' "$port" "$port"
    printf '  然后在浏览器打开：http://127.0.0.1:%s\n' "$port"
  else
    warn "服务监听 $host:$port（公网）。请务必放在 HTTPS 反代之后，并设置 WEB_COOKIE_SECURE=1。"
    printf '  访问：http://<这台服务器IP>:%s\n' "$port"
  fi
}

install_app() {
  require_root; require_systemd; ensure_deps
  [[ ! -L "$CURRENT" ]] || { info "检测到已安装，执行更新"; update_app; return; }
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$ROOT" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  install -d -o root -g "$SVC_USER" -m 0750 "$ROOT" "$ROOT/releases"
  local release; release="$ROOT/releases/$(date +%Y%m%d%H%M%S)"
  fetch_release "$release"
  write_env
  activate_release "$release"
  write_cli
  ok "NodeLite Auto Deploy 安装完成"
  printf '\n  管理员用户名：%s\n  管理员密码：%s\n  （密码只显示这一次，请立即保存；忘记可运行 nladmin password 重置）\n' \
    "$NLAD_SHOW_USER" "$NLAD_SHOW_PASSWORD"
  print_access
  printf '\n  管理命令：nladmin status|logs|update|restart|password|info|records|forget-passwords|uninstall\n\n'
}

update_app() {
  require_root; require_systemd
  [[ -f "$ENV_FILE" && -L "$CURRENT" ]] || die "尚未安装"
  ensure_deps
  local release; release="$ROOT/releases/$(date +%Y%m%d%H%M%S)"
  fetch_release "$release"
  activate_release "$release"
  write_cli
  find "$ROOT/releases" -mindepth 1 -maxdepth 1 -type d ! -samefile "$release" -mmin +1 -print0 2>/dev/null \
    | xargs -0 -r ls -dt | tail -n +3 | xargs -r rm -rf
  ok "更新完成"
}

reset_password() {
  require_root
  [[ -f "$ENV_FILE" ]] || die "尚未安装"
  local password="${1:-}"
  [[ -n "$password" ]] || password="$(random_password)"
  [[ ${#password} -ge 14 ]] || die "密码至少 14 位"
  set_key WEB_ADMIN_PASSWORD "$password"
  set_key WEB_SESSION_SECRET "$(random_secret)"
  systemctl restart "$APP.service"
  wait_healthy || die "重启后服务未就绪"
  printf '用户名：%s\n新密码：%s\n（所有已登录会话已失效）\n' "$(read_key WEB_ADMIN_USER)" "$password"
}

uninstall_app() {
  require_root
  if [[ "${NLAD_ASSUME_YES:-0}" != 1 ]]; then
    local answer; read -r -p "输入 YES 确认卸载 NodeLite Auto Deploy（不影响已部署的远程服务器）: " answer
    [[ "$answer" == YES ]] || { warn "已取消"; exit 0; }
  fi
  local purge="${NLAD_PURGE_DATA:-}"
  if [[ -d "$DATA_DIR" && -z "$purge" ]]; then
    if [[ "${NLAD_ASSUME_YES:-0}" == 1 ]]; then
      purge=0
    else
      local answer
      read -r -p "是否同时删除服务器记录数据目录 $DATA_DIR（含加密保存的 SSH/面板密码，不可恢复）？输入 YES 删除，直接回车保留: " answer
      [[ "$answer" == YES ]] && purge=1 || purge=0
    fi
  fi
  systemctl disable --now "$APP.service" 2>/dev/null || true
  rm -f "$UNIT" "$BIN" "$ENV_FILE"
  systemctl daemon-reload 2>/dev/null || true
  rm -rf --one-file-system "$ROOT"
  if [[ "$purge" == 1 ]]; then
    rm -rf --one-file-system "$DATA_DIR"
    ok "已删除数据目录 $DATA_DIR"
  elif [[ -d "$DATA_DIR" ]]; then
    chown -R root:root "$DATA_DIR"
    warn "已保留数据目录 $DATA_DIR（属主改为 root）。其中保存了加密的服务器密码，不需要时请手动删除"
  fi
  userdel "$SVC_USER" 2>/dev/null || true
  ok "已卸载"
}

case "${1:-install}" in
  install) install_app ;;
  update) update_app ;;
  uninstall) uninstall_app ;;
  password) reset_password "${2:-}" ;;
  info) print_access ;;
  *) die "用法: install.sh [install|update|uninstall|password|info]" ;;
esac
