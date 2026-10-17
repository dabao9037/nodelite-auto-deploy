# NodeLite 一键部署（nodelite-auto-deploy）

一个自托管的小网页：填入服务器 IP、SSH 端口、用户名和密码，后端通过 SSH 自动安装 [NodeLite](https://github.com/dabao9037/nodelite)、关闭 IPv6，然后在页面上返回 NodeLite 面板地址、管理员用户名和密码。

部署过的服务器会保存为「服务器记录」，以后随时可以查看面板信息，并在浏览器里一键打开 SSH 终端连接服务器。

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

部署成功后会自动保存到「服务器记录」标签页（见下文）；本页的部署结果最多在内存中保留 `TASK_RESULT_TTL_SECONDS`（默认 15 分钟）。

「保存 SSH 密码（加密存储，用于以后一键连接）」默认勾选；不勾选时 SSH 密码只在内存中用于本次部署。

## 服务器记录

每台服务器（按 地址 + SSH 端口 + 用户名 区分）一条记录，重新部署会更新这条记录并追加一条部署历史（时间、结果、NodeLite 版本、简短错误，保留最近 50 次）。

- 记录内容：地址:端口、用户、首次/最近部署时间、最近状态、NodeLite 版本、IPv6 状态、面板地址（可点击）、面板用户名和密码、SSH 主机密钥 SHA256 指纹
- 面板密码默认隐藏，点「显示」或「复制」时才向后端单独请求（POST + CSRF）
- 部署成功但某个非致命步骤有警告（如关闭 IPv6 失败），也会保存，状态显示「成功（有警告）」
- 部署失败也会写入历史；只有 SSH 登录成功后才会新建服务器记录（密码错、连不上不会留下记录）
- 按钮：**连接服务器**（打开网页终端）、**重新部署**（自动填好表单；已保存密码时密码框可留空）、**查看历史**、**删除保存的 SSH 密码**、**删除记录**

数据保存在 `WEB_DATA_DIR`（默认 `/var/lib/nodelite-auto-deploy`，systemd `StateDirectory`，目录 0700、文件 0600，属主 `nlad`）：

| 文件 | 内容 |
| --- | --- |
| `data.db` | SQLite：服务器记录和部署历史。SSH 密码和面板密码用 AES-256-GCM 加密，其余字段明文 |
| `secret.key` | 32 字节随机密钥，首次启动时生成。**丢失后已保存的密码无法解密**；备份时请和 `data.db` 一起备份并妥善保管 |

旧版本升级上来没有任何记录，这是正常的；之后部署的服务器才会出现。

### 主机密钥校验

首次部署时记录 SSH 主机密钥指纹，之后的重新部署和网页终端都会**校验**：不一致时直接拒绝（在发送密码之前），并在记录卡片和终端页显示红色警告和新旧指纹。确认是自己重装了系统后，点「信任新密钥」才会替换。请先在服务商的 VNC/救援控制台执行 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` 核对。

### 网页 SSH 终端（连接服务器）

在记录上点「连接服务器」会打开全屏终端页（xterm.js），使用保存的 SSH 密码登录（`xterm-256color`，窗口大小自动同步）。

- 没有保存密码时会提示输入；输入的密码只用于这一次，勾选「保存 SSH 密码」并登录成功后才会保存
- 30 分钟无操作自动断开（`TERMINAL_IDLE_SECONDS`，心跳不算操作），同时最多 `MAX_TERMINALS`（默认 4）个终端（后台保留的也算）
- 断线自动重连、不丢会话：手机切后台、锁屏、换网络导致断线时，服务器上的 SSH 会话不会关闭，而是在后台保留 `TERMINAL_RESUME_SECONDS`（默认 600 秒）并缓存期间的输出（约 256KB）。页面显示「重连中」并自动重连（1s、2s、4s… 最长 15s 退避；切回页面或网络恢复时立即重连），回到同一个 shell 并补上断线期间的输出，不需要重新登录。超时后自动用保存的密码重新登录一个新会话
- 每 20 秒双向心跳，防止手机网络 / NAT / 代理掐断空闲连接；45 秒收不到任何消息就判定断线并重连
- 续接令牌是随机值，绑定当前登录会话和服务器记录，只存在本标签页的 sessionStorage，不进 URL 和日志；退出登录、点「断开连接」、远程 shell 退出、空闲超时都会立即真正关闭会话。同一个会话只能在一个页面里打开，后打开的会把先前的挤下线
- 连接流程：页面先 POST（带 CSRF）申请一张 60 秒内有效、只能用一次、绑定当前登录会话的票据，再建立 WebSocket 并把票据作为第一条消息发送（不放在 URL 里，不会进入访问日志）；握手时还会校验登录 Cookie 和 Origin 必须与 Host 一致
- 放在 nginx 后面时，`location` 需要支持 WebSocket：

```nginx
location /你的根路径/ {
    proxy_pass http://127.0.0.1:8780;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

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
nladmin records     # 显示服务器记录数量、保存了 SSH 密码的数量
nladmin forget-passwords   # 删除所有记录里保存的 SSH 密码（记录和面板信息保留），-y 跳过确认
nladmin uninstall   # 卸载本程序（不影响已部署的远程服务器）；会询问是否删除数据目录
```

## 安全说明（保存密码后请务必阅读）

- 本程序现在会**加密保存服务器的 root SSH 密码**（勾选保存时）和 NodeLite 面板密码。密钥 `secret.key` 和数据库在同一台机器上，**任何拿到这台机器 root 权限的人都能解密全部密码**。加密防的是数据库文件单独泄露（备份、误拷贝），防不了本机被攻破
- 网页管理员密码等于所有已保存服务器的 root 权限：请保持强密码，定期用 `nladmin password` 更换；不要和其他网站共用
- 不想再保存任何 SSH 密码：`nladmin forget-passwords`；单台服务器可在记录卡片上点「删除保存的 SSH 密码」。之后部署或连接时再手动输入即可
- 卸载时（`nladmin uninstall`）会询问是否删除数据目录；选择保留时目录属主改为 root，不需要时请手动删除 `/var/lib/nodelite-auto-deploy`
- 网页终端拥有和 SSH 登录完全相同的权限，请只在可信的设备和网络上使用，用完点「断开连接」

## 安全设计

- 网页本身需要管理员登录；登录有频率限制，登录表单和所有 API POST 都有 CSRF 校验，并拒绝跨站 Origin
- 会话 Cookie：HttpOnly、SameSite=Strict，可开启 Secure；严格 CSP，禁止被嵌入
- 未勾选保存时，SSH 密码只在内存中交给 paramiko 认证，认证后立即丢弃引用；勾选保存时只在 SSH 登录成功后以 AES-256-GCM 加密写入 `data.db`（记录 id + 字段名作为附加认证数据，密文不能挪到别的记录上用）。任何情况下都不写日志，不放进命令行或环境变量，不存浏览器（前端不使用 localStorage/sessionStorage，提交后清空输入框）
- 列表接口从不返回密码；面板密码只能通过带 CSRF 的 POST 单独获取
- 校验错误不回显请求内容；日志里的密码类字段、SSH 密码和面板密码全部打码
- 任务结果仅存内存，绑定登录会话，到期自动清除
- 默认拒绝内网/回环/链路本地等目标（防 SSRF），可用 `ALLOW_PRIVATE_TARGETS=1` 放开内网（回环始终禁止），或用 `TARGET_ALLOWLIST_CIDRS` 限定网段；域名只解析一次并固定 IP，防 DNS rebinding
- 限制同时运行任务数（`MAX_CONCURRENT_TASKS`）和创建频率
- 输入校验：端口 1-65535，用户名 `[A-Za-z_][A-Za-z0-9_.-]{0,31}`，主机只接受 IP 或合法域名
- SSH 主机密钥：首次连接自动信任（TOFU）并记录指纹，之后的连接校验指纹，不一致拒绝连接，需要人工点「信任新密钥」
- CSP 禁止外部 CDN：xterm.js 本地托管；`connect-src` 只允许本站和同主机的 ws/wss；终端页 xterm 动态插入的样式用每次请求随机的 nonce 放行，不使用 `unsafe-inline`
- systemd 服务以 `nlad` 用户运行，`ProtectSystem=strict`、`NoNewPrivileges` 等加固，只有 `StateDirectory`（`/var/lib/nodelite-auto-deploy`）可写

## 已知限制

- 仅支持密码登录 SSH（不支持私钥）
- 主机密钥为 TOFU，无法防御首次连接时的中间人，请核对指纹
- 网页终端不支持文件上传/下载，也不支持 SSH 私钥登录
- 只在 x86_64/arm64 + systemd 的 Linux 上安装 NodeLite（NodeLite 本身的要求）
- 部分容器/OpenVZ 不允许修改 IPv6 sysctl，此时关闭 IPv6 会显示失败警告，但不影响安装结果

## 开发

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
ruff check app tests
shellcheck install.sh nladmin
```

## 许可

MIT

### 第三方组件（本地托管于 `app/static/vendor/xterm/`）

| 组件 | 版本 | 许可 | 来源 |
| --- | --- | --- | --- |
| @xterm/xterm（`xterm.js`、`xterm.css`） | 5.5.0 | MIT（`LICENSE-xterm`） | `https://registry.npmjs.org/@xterm/xterm/-/xterm-5.5.0.tgz`，sha512 `hqJHYaQb5OptNunnyAnkHyM8aCjZ1MEIDTQu1iIbbTD/xops91NB5yq1ZK/dC2JDbVWtF23zUtl9JE2NqwT87A==` |
| @xterm/addon-fit（`addon-fit.js`） | 0.10.0 | MIT（`LICENSE-addon-fit`） | `https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.10.0.tgz`，sha512 `UFYkDm4HUahf2lnEyHvio51TNGiLK66mqP2JoATy7hRZeXaGMRDr00JiSF7m63vR5WKATF605yEggJKsw0JpMQ==` |

Python 依赖新增 `cryptography==50.0.2`（与 paramiko 4.0.0 已依赖的版本一致）和 `wsproto==1.3.2`（uvicorn 0.35.0 的 WebSocket 实现，启动时固定 `ws="wsproto"`）。
