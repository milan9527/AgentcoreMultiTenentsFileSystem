#!/usr/bin/env python3
"""
jail.py - 租户代码执行沙箱 (mount namespace + pivot_root)

被 main.py 作为独立进程 exec，用于执行租户提供的命令/代码。

隔离原理（与旧版 bind-mount 到 /workspace 的关键区别）：
    旧版把租户目录 *映射* 到 /workspace，但 /mnt/shared 仍然挂在同一个
    mount namespace 里 —— 租户用绝对路径 /mnt/shared/tenants/<其他租户>
    可以直接读写。映射不等于隐藏。

    本模块为每次执行创建独立 mount namespace，用 pivot_root 换根到一个
    tmpfs 上现搭的 jail，jail 里根本不存在 /mnt/shared，也不存在其他租户的
    任何路径。租户目录是 jail 内唯一可写、唯一承载数据的位置。
    换根后 detach 旧 root，因此不存在 chroot 逃逸的经典手法。

分层：
    1. mount namespace + pivot_root  → 文件系统视图里只有 /workspace
    2. 丢弃全部 capability + no_new_privs → 无 CAP_SYS_ADMIN，无法重新 mount/chroot 逃逸
    3. PID/IPC/UTS namespace → 看不到、杀不到宿主进程
    4. rlimit → CPU / 文件大小 / 进程数 / core 限制
    5. env 白名单 → 不向租户代码泄漏 AWS 凭证等宿主环境

保持 uid 0 而不降权到 nobody：EFS Access Point 是 Uid=0/Gid=0，租户文件
属主为 root，降权后租户将无法写自己的目录。丢弃所有 capability 后的 uid 0
仍受 pivot_root 约束（逃逸所需的 CAP_SYS_ADMIN / CAP_SYS_CHROOT 已不存在），
同时保留对自己文件的 DAC 属主权限。

退出码 126 = jail 无法建立（fail closed，绝不退化为无隔离执行）。
"""

import argparse
import ctypes
import ctypes.util
import errno
import os
import platform
import resource
import shutil
import signal
import sys

# ─── 常量 ─────────────────────────────────────────────────────────

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWPID = 0x20000000

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

MNT_DETACH = 2

PR_SET_PDEATHSIG = 1
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38

_LINUX_CAPABILITY_VERSION_3 = 0x20080522

# jail 挂载点（Dockerfile 预创建）
JAIL_DIR = "/jail"

# 从宿主 rootfs 只读引入的系统目录（解释器、共享库所需）
# 注意：不包含 /app（runtime 源码）、不包含 /mnt（EFS）、不包含 /root /home /var
SYSTEM_RO_DIRS = ("/usr", "/lib", "/lib64", "/lib32", "/libx32", "/bin", "/sbin", "/opt")

# 复制进 jail 的最小 /etc 文件（不整体 bind /etc）
# 注意不含 passwd/group：宿主的这两个文件会泄漏宿主用户名，改为下方合成最小版本
ETC_FILES = ("hosts", "hostname", "resolv.conf",
             "nsswitch.conf", "localtime", "ld.so.conf", "ld.so.cache")

# 合成的最小 passwd/group —— 只有 root，解释器 getpwuid() 可用，不泄漏宿主账号
SYNTHETIC_PASSWD = "root:x:0:0:root:/workspace:/bin/bash\n"
SYNTHETIC_GROUP = "root:x:0:\n"
# TLS 根证书目录（https 出网需要）
ETC_RO_DIRS = ("ssl", "ca-certificates", "pki", "ld.so.conf.d")

DEV_NODES = ("null", "zero", "full", "random", "urandom", "tty")

# 允许透传给租户代码的环境变量名白名单
ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TZ", "TERM")

JAIL_SETUP_FAILED = 126

# ─── libc 绑定 ────────────────────────────────────────────────────

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

_libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                        ctypes.c_ulong, ctypes.c_void_p]
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.unshare.argtypes = [ctypes.c_int]
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong]
_libc.syscall.restype = ctypes.c_long

# glibc 不导出 pivot_root，必须走 syscall；capset 视版本可能缺失
_SYSCALL_NR = {
    "aarch64": {"pivot_root": 41, "capset": 91},
    "x86_64": {"pivot_root": 155, "capset": 126},
}


def _b(s):
    if s is None:
        return None
    return s.encode() if isinstance(s, str) else s


def _chk(rc, what):
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"{what}: {os.strerror(e)}")


def _syscall_nr(name):
    arch = platform.machine()
    try:
        return _SYSCALL_NR[arch][name]
    except KeyError:
        raise OSError(errno.ENOSYS, f"{name} syscall number unknown for arch {arch}")


def unshare(flags):
    _chk(_libc.unshare(flags), f"unshare({flags:#x})")


def mount(source, target, fstype, flags, data=None):
    _chk(_libc.mount(_b(source), _b(target), _b(fstype), ctypes.c_ulong(flags), _b(data)),
         f"mount({source} -> {target})")


def umount2(target, flags):
    _chk(_libc.umount2(_b(target), flags), f"umount2({target})")


def pivot_root(new_root, put_old):
    ctypes.set_errno(0)
    rc = _libc.syscall(ctypes.c_long(_syscall_nr("pivot_root")),
                       ctypes.c_char_p(_b(new_root)), ctypes.c_char_p(_b(put_old)))
    _chk(rc, f"pivot_root({new_root}, {put_old})")


def prctl(option, arg2=0, arg3=0, arg4=0, arg5=0):
    _chk(_libc.prctl(option, arg2, arg3, arg4, arg5), f"prctl({option})")


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def drop_all_capabilities():
    """
    清空 capability bounding set + 三个 capability 集合。

    这是保持 uid 0 仍然安全的关键：没有 CAP_SYS_ADMIN 就无法 mount，
    没有 CAP_SYS_CHROOT 就无法 chroot，逃逸 pivot_root 的常规路径全部关闭。
    """
    # bounding set：逐个 drop，超出最后一个 cap 时返回 EINVAL，正常终止
    for cap in range(0, 64):
        try:
            prctl(PR_CAPBSET_DROP, cap)
        except OSError as e:
            if e.errno == errno.EINVAL:
                break
            raise

    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()  # version 3 需要 2 个 __u32 组
    ctypes.set_errno(0)
    capset = getattr(_libc, "capset", None)
    if capset is not None:
        capset.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        rc = capset(ctypes.byref(header), ctypes.byref(data))
    else:
        rc = _libc.syscall(ctypes.c_long(_syscall_nr("capset")),
                           ctypes.byref(header), ctypes.byref(data))
    _chk(rc, "capset")


# ─── jail 构建 ────────────────────────────────────────────────────

def _bind_ro(source, target):
    os.makedirs(target, exist_ok=True)
    mount(source, target, None, MS_BIND)
    mount("none", target, None, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV)


def build_jail(jail_dir, tenant_root, workspace, tmp_size_mb):
    """
    在 jail_dir 上搭出一个新 rootfs。

    结果里存在的路径只有：只读系统目录、最小 /etc、/dev 基础节点、
    tmpfs /tmp、/proc，以及可写的 workspace（= 租户目录）。
    /mnt/shared 与其他租户目录在这个视图里不存在。
    """
    # 切断与宿主 namespace 的挂载传播，后续所有 mount 只影响本 namespace
    mount("none", "/", None, MS_REC | MS_PRIVATE)

    os.makedirs(jail_dir, exist_ok=True)
    # jail 根本身是 tmpfs —— pivot_root 要求 new_root 是挂载点
    mount("tmpfs", jail_dir, "tmpfs", MS_NOSUID | MS_NODEV, "size=16m,mode=755")

    # 只读系统目录（merged-usr 下 /bin /lib 是符号链接，照抄链接即可）
    for d in SYSTEM_RO_DIRS:
        if not os.path.exists(d):
            continue
        target = jail_dir + d
        if os.path.islink(d):
            os.symlink(os.readlink(d), target)
        else:
            _bind_ro(d, target)

    # 最小 /etc：只放解释器和 TLS 需要的文件，不整体暴露 /etc
    etc = f"{jail_dir}/etc"
    os.makedirs(etc, mode=0o755, exist_ok=True)
    for name in ETC_FILES:
        src = f"/etc/{name}"
        if os.path.isfile(src) and not os.path.islink(src):
            shutil.copyfile(src, f"{etc}/{name}")
    with open(f"{etc}/passwd", "w") as f:
        f.write(SYNTHETIC_PASSWD)
    with open(f"{etc}/group", "w") as f:
        f.write(SYNTHETIC_GROUP)
    for name in ETC_RO_DIRS:
        src = f"/etc/{name}"
        if os.path.isdir(src):
            _bind_ro(src, f"{etc}/{name}")

    # /dev 基础节点（bind 单个设备文件，避免暴露整个 /dev）
    dev = f"{jail_dir}/dev"
    os.makedirs(dev, mode=0o755, exist_ok=True)
    mount("tmpfs", dev, "tmpfs", MS_NOSUID, "size=1m,mode=755")
    for name in DEV_NODES:
        src = f"/dev/{name}"
        if not os.path.exists(src):
            continue
        target = f"{dev}/{name}"
        with open(target, "w"):
            pass
        mount(src, target, None, MS_BIND)
    for link, dest in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
                       ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")):
        os.symlink(dest, f"{dev}/{link}")

    # 可写临时空间（有容量上限，防止写满宿主）
    tmp = f"{jail_dir}/tmp"
    os.makedirs(tmp, mode=0o1777, exist_ok=True)
    mount("tmpfs", tmp, "tmpfs", MS_NOSUID | MS_NODEV, f"size={tmp_size_mb}m,mode=1777")

    # /proc 挂载点（换根后挂载，需要新 PID namespace 才是干净视图）
    os.makedirs(f"{jail_dir}/proc", mode=0o555, exist_ok=True)

    # 唯一的数据出入口：租户目录 → workspace
    ws = jail_dir + workspace
    os.makedirs(ws, mode=0o755, exist_ok=True)
    mount(tenant_root, ws, None, MS_BIND | MS_REC)
    # 保持可写，但禁止 suid / 设备文件
    mount("none", ws, None, MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV)

    # pivot_root 的 put_old 必须位于 new_root 之下
    os.makedirs(f"{jail_dir}/.oldroot", mode=0o700, exist_ok=True)


def enter_jail(jail_dir, workspace):
    """pivot_root 进 jail 并彻底 detach 旧 root"""
    pivot_root(jail_dir, f"{jail_dir}/.oldroot")
    os.chdir("/")

    # 新 PID namespace 下挂载干净的 /proc
    try:
        mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    except OSError:
        pass  # /proc 不可用不影响隔离性，交给后续代码自行处理

    # 旧 root 从本 namespace 移除 —— 这一步之后宿主文件系统真正不可达
    umount2("/.oldroot", MNT_DETACH)
    os.rmdir("/.oldroot")

    os.chdir(workspace)


def apply_limits(cpu_seconds, max_file_mb, max_procs, max_memory_mb):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
    fsize = max_file_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    resource.setrlimit(resource.RLIMIT_NPROC, (max_procs, max_procs))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    if max_memory_mb > 0:
        mem = max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))


def build_env(workspace):
    """只保留白名单变量 —— 阻断 AWS 凭证/token 等宿主环境泄漏给租户代码"""
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOWLIST}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["HOME"] = workspace
    env["TMPDIR"] = "/tmp"
    env["WORKSPACE"] = workspace
    return env


# ─── 入口 ─────────────────────────────────────────────────────────

def _run_child(args):
    """在新 namespace 的 PID 1 中：搭 jail、换根、降权、exec"""
    # 父进程（本 launcher）意外死亡时连带杀掉整个 namespace
    prctl(PR_SET_PDEATHSIG, signal.SIGKILL)

    build_jail(JAIL_DIR, args.tenant_root, args.workspace, args.tmp_size_mb)
    enter_jail(JAIL_DIR, args.workspace)

    apply_limits(args.cpu_seconds, args.max_file_mb, args.max_procs, args.max_memory_mb)

    # exec 后不得再获得任何新特权
    prctl(PR_SET_NO_NEW_PRIVS, 1)
    drop_all_capabilities()

    env = build_env(args.workspace)
    os.execve(args.argv[0], args.argv, env)


def main():
    parser = argparse.ArgumentParser(description="Run a command inside a tenant jail")
    parser.add_argument("--tenant-root", required=True)
    parser.add_argument("--workspace", default="/workspace")
    parser.add_argument("--tmp-size-mb", type=int, default=64)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    parser.add_argument("--max-file-mb", type=int, default=256)
    parser.add_argument("--max-procs", type=int, default=256)
    parser.add_argument("--max-memory-mb", type=int, default=0)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not argv:
        print("jail: no command given", file=sys.stderr)
        return JAIL_SETUP_FAILED
    args.argv = argv

    if not os.path.isdir(args.tenant_root):
        print(f"jail: tenant root not found: {args.tenant_root}", file=sys.stderr)
        return JAIL_SETUP_FAILED

    try:
        # NEWNS: 私有挂载视图；NEWPID/NEWIPC/NEWUTS: 看不到宿主进程与 IPC
        unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS)
    except OSError as e:
        print(f"jail: unshare failed ({e}); refusing to run without isolation",
              file=sys.stderr)
        return JAIL_SETUP_FAILED

    # CLONE_NEWPID 只对子进程生效，fork 后的子进程才是新 namespace 的 PID 1
    pid = os.fork()
    if pid == 0:
        try:
            _run_child(args)
        except BaseException as e:  # noqa: BLE001 - 必须 fail closed，绝不落到无隔离执行
            print(f"jail: setup failed: {type(e).__name__}: {e}", file=sys.stderr)
            os._exit(JAIL_SETUP_FAILED)
        os._exit(JAIL_SETUP_FAILED)  # execve 成功不会到这里

    def _forward(signum, _frame):
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, _forward)

    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return os.WEXITSTATUS(status)


if __name__ == "__main__":
    sys.exit(main())
