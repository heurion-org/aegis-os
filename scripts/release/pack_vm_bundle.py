#!/usr/bin/env python3
"""Builds a zero-NIC Aegis OS MicroVM guest bundle (vmlinuz + initramfs.cpio.gz + manifest.json)
from official Alpine Linux v3.21 minirootfs, linux-virt kernel/modules, CA certificates,
and a statically linked `aegis-guest-init` ELF binary installed as PID 1 `/init`.
"""
import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ALPINE_BRANCH = "v3.21"
ROOT_MODULES = [
    "virtio_pci",
    "virtio_mmio",
    "virtio-rng",
    "virtio_blk",
    "fuse",
    "virtiofs",
    "vsock",
    "vmw_vsock_virtio_transport_common",
    "vmw_vsock_virtio_transport",
]

CPIO_TYPE_DIR = 0o040000
CPIO_TYPE_REG = 0o100000
CPIO_TYPE_LNK = 0o120000


def fetch_bytes(url: str) -> bytes:
    return subprocess.check_output(
        [
            "curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-fsSL",
            "--retry",
            "3",
            "--retry-delay",
            "2",
            url,
        ],
        timeout=240,
    )


def verify_guest_init_elf(elf_bytes: bytes, arch: str) -> None:
    if len(elf_bytes) < 24 or elf_bytes[:4] != b"\x7fELF":
        raise SystemExit("guest-init binary is not a valid ELF executable")
    elf_class = elf_bytes[4]
    if elf_class != 2:
        raise SystemExit(f"expected 64-bit ELF (class 2), got class {elf_class}")
    e_machine = struct.unpack_from("<H", elf_bytes, 18)[0]
    expected = {"aarch64": 183, "x86_64": 62}[arch]
    if e_machine != expected:
        raise SystemExit(
            f"guest-init ELF architecture mismatch for {arch}: expected e_machine={expected}, got {e_machine}"
        )


def parse_alpine_minirootfs_release(yaml_text: str, arch: str) -> Tuple[str, str]:
    blocks = re.split(r"\n-\s*\n", yaml_text)
    for blk in blocks:
        kv = {}
        for line in blk.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                kv[k.strip()] = v.strip().strip('"').strip("'")
        if kv.get("flavor") == "alpine-minirootfs" and kv.get("arch") == arch:
            fname = kv.get("file")
            sha = kv.get("sha256")
            if fname and sha:
                return fname, sha.lower()
    raise SystemExit(f"could not locate alpine-minirootfs release entry for {arch}")


def parse_apkindex_packages(apkindex_tar_gz: bytes, wanted: Set[str]) -> Dict[str, str]:
    tf = tarfile.open(fileobj=io.BytesIO(apkindex_tar_gz), mode="r:gz")
    idx_file = tf.extractfile("APKINDEX")
    if idx_file is None:
        raise SystemExit("APKINDEX missing from Alpine index tarball")
    text = idx_file.read().decode("utf-8", errors="replace")
    versions: Dict[str, str] = {}
    for block in text.split("\n\n"):
        kv = {}
        for line in block.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                kv[k] = v
        pkg = kv.get("P")
        ver = kv.get("V")
        if pkg in wanted and ver:
            versions[pkg] = ver
    missing = wanted - set(versions.keys())
    if missing:
        raise SystemExit(f"missing package(s) in Alpine APKINDEX: {sorted(missing)}")
    return versions


def extract_apk_data_tar(apk_bytes: bytes) -> bytes:
    """Alpine v2 .apk files are concatenated gzip streams; the final stream is the data tarball."""
    pos = 0
    streams: List[bytes] = []
    while pos < len(apk_bytes):
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = decomp.decompress(apk_bytes[pos:])
        out += decomp.flush()
        if not decomp.eof:
            break
        streams.append(out)
        consumed = len(apk_bytes) - pos - len(decomp.unused_data)
        if consumed <= 0:
            break
        pos += consumed
    if not streams:
        raise SystemExit("failed decompressing Alpine .apk stream")
    return streams[-1]


def unwrap_kernel_image(raw: bytes, arch: str) -> bytes:
    if arch == "x86_64":
        if len(raw) > 0x210 and raw[0x202:0x206] == b"HdrS":
            return raw
        raise SystemExit("x86_64 vmlinuz-virt missing Linux bzImage 'HdrS' header")

    # aarch64: unwrap EFI zboot (`MZ..zimg`) or raw gzip into uncompressed ARM64 Image (`ARM\x64` at +0x38)
    image = raw
    if len(raw) >= 0x20 and raw[:2] == b"MZ" and raw[0x04:0x08] == b"zimg":
        offset, size = struct.unpack_from("<II", raw, 0x08)
        payload = raw[offset : offset + size]
        if payload[:2] == b"\x1f\x8b":
            image = gzip.decompress(payload)
        else:
            raise SystemExit(
                f"unsupported aarch64 zboot compression payload magic: {payload[:4]!r}"
            )
    elif raw[:2] == b"\x1f\x8b":
        image = gzip.decompress(raw)

    if len(image) <= 0x40 or image[0x38:0x3C] != b"ARM\x64":
        raise SystemExit("unwrapped aarch64 kernel image missing ARM64 magic at offset 0x38")
    return image


def normalize_mod_key(name: str) -> str:
    base = os.path.basename(name)
    for suf in (".ko.gz", ".ko.xz", ".ko.zst", ".ko"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    return base.replace("-", "_")


def resolve_modules_in_order(
    linux_tar: tarfile.TarFile, roots: List[str]
) -> List[Tuple[str, bytes]]:
    dep_member = None
    for m in linux_tar.getmembers():
        if m.name.endswith("/modules.dep") and m.isfile():
            dep_member = m
            break
    if dep_member is None:
        return []

    mod_root = os.path.dirname(dep_member.name)
    dep_text = linux_tar.extractfile(dep_member).read().decode("utf-8", "replace")
    graph: Dict[str, List[str]] = {}
    key_to_path: Dict[str, str] = {}
    for line in dep_text.splitlines():
        if ":" not in line:
            continue
        left, right = line.split(":", 1)
        rel = left.strip()
        if not rel:
            continue
        k = normalize_mod_key(rel)
        key_to_path[k] = f"{mod_root}/{rel}"
        deps = [normalize_mod_key(d) for d in right.split() if d.strip()]
        graph[k] = deps

    ordered_keys: List[str] = []
    visited: Set[str] = set()

    def visit(key: str) -> None:
        nk = normalize_mod_key(key)
        if nk in visited or nk not in key_to_path:
            return
        visited.add(nk)
        for dep in graph.get(nk, []):
            visit(dep)
        ordered_keys.append(nk)

    for r in roots:
        visit(r)

    members_by_name = {m.name: m for m in linux_tar.getmembers()}
    loaded: List[Tuple[str, bytes]] = []
    for idx, key in enumerate(ordered_keys):
        tpath = key_to_path[key]
        member = members_by_name.get(tpath)
        if member is None or not member.isfile():
            continue
        raw = linux_tar.extractfile(member).read()
        if tpath.endswith(".ko.gz"):
            ko_bytes = gzip.decompress(raw)
        elif tpath.endswith(".ko.xz"):
            ko_bytes = lzma.decompress(raw)
        elif tpath.endswith(".ko"):
            ko_bytes = raw
        else:
            raise SystemExit(f"unsupported kernel module compression in {tpath}")
        loaded.append((f"lib/aegis-modules/{idx:02d}_{key}.ko", ko_bytes))
    return loaded


def clean_cpio_path(raw: str) -> str:
    p = raw.lstrip("./")
    while "//" in p:
        p = p.replace("//", "/")
    return p.rstrip("/")


class CpioBuilder:
    def __init__(self) -> None:
        # path -> (mode, data_bytes)
        self.entries: Dict[str, Tuple[int, bytes]] = {}

    def ensure_parent_dirs(self, path: str) -> None:
        parts = path.split("/")[:-1]
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}" if cur else part
            if cur not in self.entries:
                perm = 0o1777 if cur == "tmp" else 0o0755
                self.entries[cur] = (CPIO_TYPE_DIR | perm, b"")

    def add_dir(self, path: str, perm: int = 0o0755) -> None:
        cp = clean_cpio_path(path)
        if not cp:
            return
        self.ensure_parent_dirs(cp)
        self.entries[cp] = (CPIO_TYPE_DIR | (perm & 0o7777), b"")

    def add_file(self, path: str, data: bytes, perm: int = 0o0644) -> None:
        cp = clean_cpio_path(path)
        if not cp:
            return
        self.ensure_parent_dirs(cp)
        self.entries[cp] = (CPIO_TYPE_REG | (perm & 0o7777), data)

    def add_symlink(self, path: str, target: str) -> None:
        cp = clean_cpio_path(path)
        if not cp:
            return
        self.ensure_parent_dirs(cp)
        self.entries[cp] = (CPIO_TYPE_LNK | 0o0777, target.encode("utf-8"))

    def ingest_tar(self, tar_bytes: bytes) -> None:
        tf = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*")
        for member in tf.getmembers():
            cp = clean_cpio_path(member.name)
            if not cp:
                continue
            if member.isdir():
                self.add_dir(cp, member.mode)
            elif member.issym():
                self.add_symlink(cp, member.linkname)
            elif member.islnk():
                target = "/" + clean_cpio_path(member.linkname)
                self.add_symlink(cp, target)
            elif member.isfile():
                fobj = tf.extractfile(member)
                data = fobj.read() if fobj is not None else b""
                self.add_file(cp, data, member.mode)

    def serialize_newc(self) -> bytes:
        buf = bytearray()
        ino = 1

        def append_record(name: str, mode: int, data: bytes, cur_ino: int) -> None:
            name_bytes = name.encode("utf-8") + b"\x00"
            nlink = 2 if (mode & 0o170000) == CPIO_TYPE_DIR else 1
            header = (
                f"070701"
                f"{cur_ino:08x}"
                f"{mode:08x}"
                f"{0:08x}"
                f"{0:08x}"
                f"{nlink:08x}"
                f"{0:08x}"
                f"{len(data):08x}"
                f"{0:08x}"
                f"{0:08x}"
                f"{0:08x}"
                f"{0:08x}"
                f"{len(name_bytes):08x}"
                f"{0:08x}"
            ).encode("ascii")
            buf.extend(header)
            buf.extend(name_bytes)
            while len(buf) % 4 != 0:
                buf.append(0)
            if data:
                buf.extend(data)
                while len(buf) % 4 != 0:
                    buf.append(0)

        for path in sorted(self.entries.keys()):
            mode, data = self.entries[path]
            append_record(path, mode, data, ino)
            ino += 1

        append_record("TRAILER!!!", 0, b"", 0)
        while len(buf) % 512 != 0:
            buf.append(0)
        return bytes(buf)


def write_regular_0644(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp.write_bytes(data)
    tmp.chmod(0o644)
    tmp.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser(description="Pack Aegis OS MicroVM kernel + initramfs bundle")
    ap.add_argument("--arch", required=True, choices=["aarch64", "x86_64"])
    ap.add_argument("--version", required=True)
    ap.add_argument("--guest-init", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--release-prefix", required=False, default=None)
    args = ap.parse_args()

    guest_init_bytes = args.guest_init.read_bytes()
    verify_guest_init_elf(guest_init_bytes, args.arch)

    print(f"[vm-pack] resolving Alpine {ALPINE_BRANCH} ({args.arch}) metadata...")
    rel_yaml = fetch_bytes(
        f"https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/releases/{args.arch}/latest-releases.yaml"
    ).decode("utf-8", "replace")
    mini_file, mini_sha256 = parse_alpine_minirootfs_release(rel_yaml, args.arch)

    apkindex_bytes = fetch_bytes(
        f"https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main/{args.arch}/APKINDEX.tar.gz"
    )
    pkgs = parse_apkindex_packages(apkindex_bytes, {"linux-virt", "ca-certificates-bundle"})

    print(f"[vm-pack] downloading {mini_file} ...")
    mini_bytes = fetch_bytes(
        f"https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/releases/{args.arch}/{mini_file}"
    )
    actual_mini_sha = hashlib.sha256(mini_bytes).hexdigest().lower()
    if actual_mini_sha != mini_sha256:
        raise SystemExit(
            f"alpine minirootfs SHA-256 mismatch: expected {mini_sha256}, actual {actual_mini_sha}"
        )

    linux_ver = pkgs["linux-virt"]
    ca_ver = pkgs["ca-certificates-bundle"]
    print(f"[vm-pack] downloading linux-virt={linux_ver} & ca-certificates-bundle={ca_ver} ...")
    linux_apk = fetch_bytes(
        f"https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main/{args.arch}/linux-virt-{linux_ver}.apk"
    )
    ca_apk = fetch_bytes(
        f"https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main/{args.arch}/ca-certificates-bundle-{ca_ver}.apk"
    )

    linux_tar_bytes = extract_apk_data_tar(linux_apk)
    ca_tar_bytes = extract_apk_data_tar(ca_apk)
    linux_tar = tarfile.open(fileobj=io.BytesIO(linux_tar_bytes), mode="r:")

    vmlinuz_member = linux_tar.extractfile("boot/vmlinuz-virt")
    if vmlinuz_member is None:
        raise SystemExit("boot/vmlinuz-virt missing from linux-virt package")
    vmlinuz_bytes = unwrap_kernel_image(vmlinuz_member.read(), args.arch)
    modules = resolve_modules_in_order(linux_tar, ROOT_MODULES)
    print(f"[vm-pack] resolved {len(modules)} kernel modules for virtio-fs & virtio-vsock")

    cpio = CpioBuilder()
    cpio.ingest_tar(mini_bytes)
    cpio.ingest_tar(ca_tar_bytes)
    for d in ("proc", "sys", "dev", "dev/pts", "dev/shm", "run", "etc"):
        cpio.add_dir(d, 0o0755)
    cpio.add_dir("tmp", 0o1777)
    for rel_path, ko_bytes in modules:
        cpio.add_file(rel_path, ko_bytes, 0o0644)
    cpio.add_file("etc/hosts", b"127.0.0.1 localhost\n::1 localhost\n", 0o0644)
    cpio.add_file("init", guest_init_bytes, 0o0755)
    cpio.add_symlink("sbin/aegis-guest-init", "/init")

    raw_cpio = cpio.serialize_newc()
    initramfs_gz = gzip.compress(raw_cpio, compresslevel=6, mtime=0)

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    k_path = out_dir / "vmlinuz"
    i_path = out_dir / "initramfs.cpio.gz"
    m_path = out_dir / "manifest.json"

    write_regular_0644(k_path, vmlinuz_bytes)
    write_regular_0644(i_path, initramfs_gz)
    manifest = {
        "version": args.version,
        "arch": args.arch,
        "kernel_file": "vmlinuz",
        "initramfs_file": "initramfs.cpio.gz",
        "kernel_sha256": hashlib.sha256(vmlinuz_bytes).hexdigest(),
        "initramfs_sha256": hashlib.sha256(initramfs_gz).hexdigest(),
    }
    write_regular_0644(m_path, (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))

    if args.release_prefix:
        prefix = Path(args.release_prefix)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(k_path, Path(f"{prefix}-vmlinuz"))
        shutil.copy2(i_path, Path(f"{prefix}-initramfs.cpio.gz"))
        shutil.copy2(m_path, Path(f"{prefix}-manifest.json"))

    print(
        f"[vm-pack] ready at {out_dir} (kernel={len(vmlinuz_bytes)} B, initramfs={len(initramfs_gz)} B)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
