# NodeLite 一键部署（nodelite-auto-deploy）

一个自托管的小网页：填入服务器 IP、SSH 端口、用户名和密码，后端通过 SSH 自动安装 [NodeLite](https://github.com/dabao9037/nodelite)、关闭 IPv6，然后在页面上返回 NodeLite 面板地址、管理员用户名和密码。

## 授权边界

只能用于你**拥有或已获授权管理**的服务器。提交前页面要求勾选确认。本程序不会扫描、猜测密码或批量操作，一次任务只连一台你填写的服务器。

## 一键安装（装本网页程序）

在一台 Linux（systemd，Debian/Ubuntu/RHEL 系）服务器上用 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dabao9037/nodelite-auto-deploy/main/install.sh)
```

安装器会：

- 安装 python3 / python3-venv / curl（仅缺失时）
- 创建无登录权限的系统用户 `nlad`，代码放在 `/opt/nodelite-auto-deploy`，独立 venv，依赖版本全部固定
- 生成随机管理员密码（**只显示一次**）和会话密钥，写入 `/etc/nodelite-auto-deploy.env`（0600）
- 注册并启动 systemd 服务 `nodelite-auto-deploy`（带沙箱加固）
- 默认只监听 `127.0.0.1:8780`

可选环境变量（安装前设置）：`WEB_ADMIN_USER`、`WEB_ADMIN_PASSWORD`、`WEB_LISTEN_PORT`、`ALLOW_PRIVATE_TARGETS=1`、`TARGET_ALLOWLIST_CIDRS`。

## 打开网页

默认只监听本机，在你自己的电脑上开 SSH 隧道：

```bash
ssh -N -L 8780:127.0.0.1:8780 root@<装本程序的服务器IP>
```

然后浏览器打开 <http://127.0.0.1:8780>，用安装时显示的管理员账号登录。

确实需要公网访问时：

```bash
WEB_LISTEN_HOST=0.0.0.0 WEB_ALLOW_PUBLIC_LISTEN=1 bash <(curl -fsSL https://raw.githubusercontent.com/dabao9037/nodelite-auto-deploy/main/install.sh)
```

> ⚠️ 本程序会接收服务器 root 密码。公网明文 HTTP 下密码可能被窃听，请务必放在 HTTPS 反代（Caddy/Nginx）之后，并在 env 里设置 `WEB_COOKIE_SECURE=1`。

## 使用

1. 填写服务器 IP/域名（必填）、SSH 端口（留空 22）、用户名（留空 root）、密码（必填）
2. 「关闭 IPv6」默认勾选；勾选授权确认
3. 点「开始部署」，页面实时显示 5 个步骤：连接 → 检查系统 → 安装 NodeLite → 关闭 IPv6 → 读取面板信息，并滚动显示安装日志（密码已打码）
4. 完成后显示：面板地址（可点击）、用户名、密码（均可一键复制）、SSH 主机密钥指纹、IPv6 状态、NodeLite 版本、面板可达性

结果**只显示一次**，最多在内存中保留 `TASK_RESULT_TTL_SECONDS`（默认 15 分钟），也可以点「立即从内存清除结果」。

### 远程服务器上实际执行了什么

| 步骤 | 命令（全部无 TTY、参数经 `shlex.quote`） |
| --- | --- |
| 权限 | `id -u`；非 root 时 `sudo -n true`，没有免密 sudo 直接报错 |
| 检查 | `uname`、`/etc/os-release`、systemd、curl、bash、glibc、是否已安装 NodeLite |
| 安装 | 把 `https://raw.githubusercontent.com/dabao9037/nodelite/main/install.sh` 下载到 `mktemp -d` 临时目录，校验 shebang/来源/`bash -n`，打印 SHA256，然后 `bash install.sh install </dev/null` |
| 关 IPv6 | `NODELITE_ASSUME_YES=1 bash /opt/nodelite/install.sh disable-ipv6`，再用 `sysctl -n net.ipv6.conf.all.disable_ipv6` 确认为 1 |
| 读信息 | 从 `/opt/nodelite/config/nodelite.env` 只读取 `PUBLIC_HOST/LISTEN_PORT/ACCESS_PATH/ADMIN_USER/管理员密码` 和 `/opt/nodelite/VERSION` |
| 校验 | 远程 `curl 127.0.0.1:端口/路径/login`；本程序再访问一次公网地址（6 秒超时，不跟随跳转） |

- 已安装 NodeLite 的服务器会自动按**更新**执行，保留原有账号、密码、端口和路径
- 如果你填写的是 IPv6 地址，或者 SSH 会话本身走 IPv6，会**拒绝关闭 IPv6**并说明原因（否则会把自己断开）
- 内核本身就没有 IPv6（`ipv6.disable=1`）时直接报告已关闭
- 公网访问检测失败只给出提示，不算部署失败（通常是云厂商安全组没放行面板端口）

## 管理命令

```bash
nladmin status      # 服务状态和访问方式
nladmin logs        # 实时日志
nladmin restart
nladmin update      # 从 GitHub main 更新，失败自动回滚
nladmin password    # 重置管理员密码（随机生成，所有会话失效）；也可 nladmin password '新密码'
nladmin uninstall   # 卸载本程序（不影响已部署的远程服务器）
```

## 安全设计

- 网页本身需要管理员登录；登录有频率限制，登录表单和所有 API POST 都有 CSRF 校验，并拒绝跨站 Origin
- 会话 Cookie：HttpOnly、SameSite=Strict，可开启 Secure；严格 CSP，禁止被嵌入
- SSH 密码只在内存中交给 paramiko 认证，认证后立即丢弃引用；不写日志、磁盘、数据库，不放进命令行或环境变量，不存浏览器（前端不使用 localStorage/sessionStorage，提交后清空输入框）
- 校验错误不回显请求内容；日志里的密码类字段、SSH 密码和面板密码全部打码
- 任务结果仅存内存，绑定登录会话，到期自动清除
- 默认拒绝内网/回环/链路本地等目标（防 SSRF），可用 `ALLOW_PRIVATE_TARGETS=1` 放开内网（回环始终禁止），或用 `TARGET_ALLOWLIST_CIDRS` 限定网段；域名只解析一次并固定 IP，防 DNS rebinding
- 限制同时运行任务数（`MAX_CONCURRENT_TASKS`）和创建频率
- 输入校验：端口 1-65535，用户名 `[A-Za-z_][A-Za-z0-9_.-]{0,31}`，主机只接受 IP 或合法域名
- SSH 主机密钥：首次连接自动信任（TOFU）且不保存，结果中显示 SHA256 指纹，请与服务商控制台核对
- systemd 服务以 `nlad` 用户运行，`ProtectSystem=strict`、`NoNewPrivileges` 等加固

## 已知限制

- 仅支持密码登录 SSH（不支持私钥）
- 主机密钥为 TOFU，无法防御首次连接时的中间人，请核对指纹
- 只在 x86_64/arm64 + systemd 的 Linux 上安装 NodeLite（NodeLite 本身的要求）
- 部分容器/OpenVZ 不允许修改 IPv6 sysctl，此时关闭 IPv6 会显示失败警告，但不影响安装结果
- 结果存在内存中，服务重启后丢失

## 开发

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
ruff check app tests
shellcheck install.sh nladmin
```

## 许可

MIT
