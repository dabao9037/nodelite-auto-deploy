from __future__ import annotations

import shlex
import socket

import paramiko
import pytest

from app import deployer
from app.deployer import (
    PASSWORD_KEY,
    DeploymentError,
    DeploySpec,
    Scrubber,
    SSHAdapter,
    build_info_script,
    deploy,
    remote_cmd,
)

from .conftest import make_settings

SSH_PW = "Root-Secret-Pass-777"
PANEL_PW = "PanelPw-ABCDEFGHIJ"
PREFLIGHT_OK = (
    "KERNEL=Linux\nARCH=x86_64\nOS=Ubuntu 22.04.5 LTS\nSYSTEMD=1\nCURL=1\nBASH=1\nGLIBC=2.35\n"
    "INSTALLED=0\nOLD_VERSION=\nSSH_CONN=198.51.100.2 50000 203.0.113.10 22\n"
)
INFO_OK = (
    "PUBLIC_HOST=203.0.113.10\nLISTEN_PORT=45678\nACCESS_PATH=panel-0123456789abcdef\n"
    f"ADMIN_USER=admin\n{PASSWORD_KEY}={PANEL_PW}\nVERSION=v0.3.33-native\n"
)


class Recorder:
    def __init__(self):
        self.stages: list[str] = []
        self.steps: dict[str, str] = {}
        self.lines: list[str] = []

    def stage(self, stage, message):
        self.stages.append(stage)
        self.lines.append(message)

    def step(self, stage, status):
        self.steps[stage] = status

    def info(self, message):
        self.lines.append(message)

    def log(self, line):
        self.lines.append(line)


class FakeSSH:
    """Stands in for SSHAdapter; responses are keyed by a substring of the command."""

    def __init__(self, spec, timeout, *, uid="0", sudo_ok=True, preflight=PREFLIGHT_OK, install_rc=0,
                 install_out="[+] NodeLite 原生版安装/更新完成\n密码：" + PANEL_PW + "\n",
                 ipv6_rc=0, sysctl="1", info=INFO_OK, curl_code="200", peer_ipv6=False):
        self.spec = spec
        self.commands: list[str] = []
        self.fingerprint = "SHA256:fakefingerprint"
        self.key_type = "ssh-ed25519"
        self.connected_address = spec.resolved_addresses[0]
        self.peer_is_ipv6 = peer_ipv6
        self.closed = False
        self.cfg = dict(uid=uid, sudo_ok=sudo_ok, preflight=preflight, install_rc=install_rc,
                        install_out=install_out, ipv6_rc=ipv6_rc, sysctl=sysctl, info=info, curl_code=curl_code)
        self.password_seen = None

    def connect(self):
        self.password_seen = self.spec.ssh_password
        self.spec.ssh_password = None

    def close(self):
        self.closed = True

    def run(self, command, *, timeout=60, on_line=None):
        self.commands.append(command)
        c = self.cfg
        if command == "id -u":
            return 0, c["uid"] + "\n"
        if command == "sudo -n true":
            return (0 if c["sudo_ok"] else 1), ""
        if "KERNEL=" in command:
            return 0, c["preflight"]
        if "nodelite-auto" in command:
            for line in c["install_out"].splitlines():
                on_line and on_line(line)
            return c["install_rc"], c["install_out"]
        if "disable-ipv6" in command:
            on_line and on_line("[+] IPv6 已关闭")
            return c["ipv6_rc"], ""
        if "disable_ipv6" in command:
            return 0, c["sysctl"] + "\n"
        if "nodelite.env" in command:
            return 0, c["info"]
        if "curl" in command and "%{http_code}" in command:
            return 0, c["curl_code"]
        raise AssertionError(f"unexpected command {command}")


def spec(**extra):
    values = dict(
        host="203.0.113.10", resolved_addresses=("203.0.113.10",), typed_ipv6=False,
        ssh_port=22, ssh_user="root", ssh_password=SSH_PW, disable_ipv6=True,
    )
    values.update(extra)
    return DeploySpec(**values)


def run_deploy(s=None, probe=lambda url, st: (None, "skip"), **fake):
    s = s or spec()
    holder = {}

    def factory(sp, timeout):
        holder["ssh"] = FakeSSH(sp, timeout, **fake)
        return holder["ssh"]

    rec = Recorder()
    result = deploy(s, rec, make_settings(), ssh_factory=factory, public_probe=probe)
    return result, rec, holder["ssh"], s


def test_happy_path_returns_panel_info_and_drops_password():
    result, rec, ssh, s = run_deploy()
    assert result["panel_url"] == "http://203.0.113.10:45678/panel-0123456789abcdef/login"
    assert result["username"] == "admin" and result["password"] == PANEL_PW
    assert result["version"] == "v0.3.33-native"
    assert result["ipv6"]["disabled"] is True
    assert result["fingerprint"].startswith("SHA256:")
    assert result["mode"] == "install"
    assert rec.stages == ["connect", "preflight", "install", "ipv6", "info"]
    assert ssh.closed and s.ssh_password is None and ssh.password_seen == SSH_PW
    # Panel password never appears in the streamed log
    assert not any(PANEL_PW in line for line in rec.lines)
    assert not any(SSH_PW in cmd for cmd in ssh.commands)
    ipv6_cmd = next(c for c in ssh.commands if "disable-ipv6" in c)
    assert ipv6_cmd == "env NODELITE_ASSUME_YES=1 bash /opt/nodelite/install.sh disable-ipv6"
    install_cmd = next(c for c in ssh.commands if "nodelite-auto" in c)
    argv = shlex.split(install_cmd)
    assert argv[0:2] == ["bash", "-c"] and argv[-2:] == [
        "https://raw.githubusercontent.com/dabao9037/nodelite/main/install.sh", "203.0.113.10",
    ]
    assert 'bash "$work/install.sh" install </dev/null' in argv[2]


def test_existing_install_runs_update_without_overriding_host():
    preflight = PREFLIGHT_OK.replace("INSTALLED=0", "INSTALLED=1").replace("OLD_VERSION=", "OLD_VERSION=v0.3.30-native")
    result, rec, ssh, _ = run_deploy(preflight=preflight)
    assert result["mode"] == "update"
    install_cmd = next(c for c in ssh.commands if "nodelite-auto" in c)
    assert shlex.split(install_cmd)[-1] == ""
    assert any("保留现有账号密码" in line for line in rec.lines)


def test_non_root_without_sudo_fails_clearly():
    with pytest.raises(DeploymentError, match="免密 sudo"):
        run_deploy(spec(ssh_user="ubuntu"), uid="1000", sudo_ok=False)


def test_non_root_with_sudo_prefixes_commands():
    _, _, ssh, _ = run_deploy(spec(ssh_user="ubuntu"), uid="1000", sudo_ok=True)
    install_cmd = next(c for c in ssh.commands if "nodelite-auto" in c)
    assert install_cmd.startswith("sudo -n -- bash -c ")
    assert next(c for c in ssh.commands if "disable-ipv6" in c).startswith("sudo -n -- env NODELITE_ASSUME_YES=1")


@pytest.mark.parametrize(
    "replace,match",
    [
        (("SYSTEMD=1", "SYSTEMD=0"), "systemd"),
        (("CURL=1", "CURL=0"), "curl"),
        (("ARCH=x86_64", "ARCH=mips"), "架构"),
        (("KERNEL=Linux", "KERNEL=FreeBSD"), "Linux"),
    ],
)
def test_preflight_failures(replace, match):
    with pytest.raises(DeploymentError, match=match):
        run_deploy(preflight=PREFLIGHT_OK.replace(*replace))


def test_install_failure_is_scrubbed():
    out = f"[x] boom\n密码：{PANEL_PW}\nsomething {SSH_PW}\n"
    with pytest.raises(DeploymentError) as info:
        run_deploy(install_rc=1, install_out=out)
    assert PANEL_PW not in str(info.value) and SSH_PW not in str(info.value)
    assert "退出码 1" in str(info.value)


def test_ipv6_skipped_when_user_typed_ipv6():
    s = spec(host="2001:db8::10", resolved_addresses=("2001:db8::10",), typed_ipv6=True)
    result, _, ssh, _ = run_deploy(s)
    assert result["ipv6"]["disabled"] is False and "IPv6 地址" in result["ipv6"]["message"]
    assert not any("disable-ipv6" in c for c in ssh.commands)
    assert result["panel_url"].startswith("http://203.0.113.10:")


def test_ipv6_skipped_when_session_is_ipv6_server_side():
    preflight = PREFLIGHT_OK.replace("SSH_CONN=198.51.100.2 50000 203.0.113.10 22", "SSH_CONN=2001:db8::2 50000 2001:db8::10 22")
    result, _, ssh, _ = run_deploy(preflight=preflight)
    assert result["ipv6"]["disabled"] is False and "会话" in result["ipv6"]["message"]
    assert not any("disable-ipv6" in c for c in ssh.commands)


def test_ipv6_skipped_when_peer_ipv6():
    result, _, ssh, _ = run_deploy(peer_ipv6=True)
    assert result["ipv6"]["disabled"] is False
    assert not any("disable-ipv6" in c for c in ssh.commands)


def test_ipv6_not_requested():
    result, rec, ssh, _ = run_deploy(spec(disable_ipv6=False))
    assert result["ipv6"]["requested"] is False
    assert rec.steps["ipv6"] == "skipped"
    assert not any("disable-ipv6" in c for c in ssh.commands)


def test_ipv6_failure_is_warning_not_fatal():
    result, rec, _, _ = run_deploy(ipv6_rc=1, sysctl="0")
    assert result["ipv6"]["disabled"] is False and "失败" in result["ipv6"]["message"]
    assert rec.steps["ipv6"] == "warn"


def test_ipv6_stack_absent_counts_as_disabled():
    result, rec, ssh, _ = run_deploy(preflight=PREFLIGHT_OK + "IPV6_STACK=0\n")
    assert result["ipv6"]["disabled"] is True and "内核" in result["ipv6"]["message"]
    assert not any("disable-ipv6" in c for c in ssh.commands)


def test_domain_target_adds_alt_url_when_public_host_differs():
    s = spec(host="vps.example.com", resolved_addresses=("203.0.113.10",))
    result, _, _, _ = run_deploy(s)
    assert result["alt_panel_url"] == "http://vps.example.com:45678/panel-0123456789abcdef/login"


def test_incomplete_env_rejected():
    with pytest.raises(DeploymentError, match=PASSWORD_KEY):
        run_deploy(info=INFO_OK.replace(f"{PASSWORD_KEY}={PANEL_PW}", f"{PASSWORD_KEY}="))


def test_invalid_access_path_rejected():
    with pytest.raises(DeploymentError, match="ACCESS_PATH"):
        run_deploy(info=INFO_OK.replace("panel-0123456789abcdef", "../../etc"))


def test_public_probe_failure_is_reported_not_fatal():
    result, _, _, _ = run_deploy(probe=lambda url, st: (False, "安全组未放行"))
    assert result["reachability"]["public"] is False
    assert result["reachability"]["local"] is True


def test_info_script_reads_only_expected_keys():
    script = build_info_script()
    assert "APP_SECRET" not in script and "/opt/nodelite/config/nodelite.env" in script


def test_remote_cmd_quotes_everything():
    assert remote_cmd(["echo", "a b; rm -rf /"], False) == "echo 'a b; rm -rf /'"
    assert remote_cmd(["id"], True) == "sudo -n -- id"


def test_scrubber_masks_password_lines_and_ansi():
    s = Scrubber()
    s.add("topsecret")
    assert s("\x1b[0;32m[+]\x1b[0m 密码：abc123") == "[+] 密码：[已隐藏]"
    assert s("x topsecret y") == "x [已隐藏] y"
    assert "zzz" not in s("ADMIN_PASSWORD=zzz")


# --- SSHAdapter with a mocked paramiko --------------------------------------------------


class FakeKey:
    def asbytes(self):
        return b"key-bytes"

    def get_name(self):
        return "ssh-ed25519"


class FakeTransport:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def get_remote_server_key(self):
        return FakeKey()

    def set_keepalive(self, _):
        pass


class FakeClient:
    instances: list = []
    fail_auth = False

    def __init__(self):
        self.kwargs = None
        self.policy = None
        self.closed = False
        self.transport = FakeTransport()
        FakeClient.instances.append(self)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.kwargs = kwargs
        if FakeClient.fail_auth:
            raise paramiko.AuthenticationException("bad")

    def get_transport(self):
        return self.transport

    def close(self):
        self.closed = True
        self.transport.sock.close()


def test_ssh_adapter_tofu_fingerprint_and_password_drop(monkeypatch):
    monkeypatch.setattr(deployer.paramiko, "SSHClient", FakeClient)
    FakeClient.instances.clear()
    FakeClient.fail_auth = False
    s = spec()
    adapter = SSHAdapter(s, 5)
    adapter.connect()
    client = FakeClient.instances[0]
    assert client.kwargs["password"] == SSH_PW
    assert client.kwargs["look_for_keys"] is False and client.kwargs["allow_agent"] is False
    assert client.kwargs["timeout"] == 5
    assert not isinstance(client.policy, paramiko.RejectPolicy)
    assert adapter.fingerprint.startswith("SHA256:") and "=" not in adapter.fingerprint
    assert s.ssh_password is None
    adapter.close()
    assert client.closed


def test_ssh_adapter_auth_failure_message(monkeypatch):
    monkeypatch.setattr(deployer.paramiko, "SSHClient", FakeClient)
    FakeClient.fail_auth = True
    s = spec()
    with pytest.raises(DeploymentError, match="认证失败"):
        SSHAdapter(s, 5).connect()
    assert s.ssh_password is None
    FakeClient.fail_auth = False
