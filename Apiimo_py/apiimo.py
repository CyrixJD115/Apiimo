#!/usr/bin/env python3
"""
Apiimo - Aniimo (Unity IL2CPP) reverse engineering toolkit.

Main library for:
  1. Decrypting Aniimo's obfuscated global-metadata.dat (custom 1152-byte
     repeating-XOR keystream, reordered sections, modified v31 header).
  2. Rebuilding a vanilla metadata header so Il2CppDumper accepts it.
  3. Running the full dump pipeline (dump.cs / script.json / il2cpp.h /
     stringliteral.json / DummyDll).
  4. Post-dump queries: classes/methods/fields, method -> VA resolution.
  5. Binary patching primitives for GameAssembly.dll (VA <-> file offset).

Commands:
  dump                        full pipeline -> <out> (default: <game>/.dump)
  classes <regex>             list matching classes
  methods <regex>             list matching methods with VA
  fields <ClassRegex>         dump a class layout (fields + offsets)
  addr <SubStr>               resolve method addresses from script.json
  str <regex>                 search string literals
  va2off <va_hex>             GameAssembly.dll VA -> file offset
  off2va <off_hex>            file offset -> VA
  patch <va_hex> <hexbytes>   patch GameAssembly.dll in place
  discover                    experimental: rediscover section layout

Options:
  --out <dir>                 output directory (default: <game>/.dump)
  --game <dir>                game root (default: parent of this script)

Requires: python3, numpy, il2cpp-dumper on PATH (for `dump`).
"""

import json
import os
import re
import struct
import subprocess
import sys

import numpy as np

# ---------------------------------------------------------------------------
# Build constants (Aniimo, Unity 2022.3.62f1, metadata v31, binaay build)
# ---------------------------------------------------------------------------

METADATA_REL = "Aniimo_Data/il2cpp_data/Metadata/global-metadata.dat"
BINARY_REL = "GameAssembly.dll"
IMAGE_BASE = 0x180000000
SANITY = 0xFAB11BAF
VERSION = 31
KEY_PERIOD = 1152
TYPE_COUNT = 28348
FIELD_COUNT = 166873
PARAM_COUNT = 213031
METHOD_COUNT = 211214
IMAGE_COUNT = 133
ASSEMBLY_COUNT = 132
TYPES_IN_BINARY = 18606   # MetadataRegistration.typesCount

OUT_DIR = ".dump"
DEC_NAME = "global-metadata.decrypted.dat"

PATTERN = re.compile(r"^20[12][0-9]\.[0-9]+\.[0-9]+[a-z][0-9]+$")

# Recovered keystream (1152 bytes), phase-aligned to file offset 256.
EMBEDDED_KEY_HEX = (
    "88de9c85c7d93fa45b28b226ae54754f99f8d10ee344fe1baf0753a0cec6b212"
    "414a80d57cca3de5f3c2ad7ece704181858814713867ac57972ab67f9e05fe1a"
    "6a8a71d2237a9e4ac099c59911615c01f91cf20e77e6a77ffbe391e90e59d8d0"
    "0544f0c0686230054becf9281203ab3fc5f69cb30838cf50476faa5a511ce741"
    "96de9c85d8d93fa4f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a"
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d"
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83"
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e"
    "0716a3d62450d983f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a"
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d"
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83"
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e"
    "0716a3d62450d9835b28b226ae54754f99f8d10ee344fe1baf0753a0cec6b212"
    "414a80d57cca3de5f3c2ad7ece704181858814713867ac57972ab67f9e05fe1a"
    "6a8a71d2237a9e4ac099c59911615c01f91cf20e77e6a77ffbe391e90e59d8d0"
    "0544f0c0686230054becf9281203ab3fc5f69cb30838cf50476faa5a511ce741"
    "96de9c85d8d93fa45b28b226ae54754f99f8d10ee344fe1baf0753a0cec6b212"
    "414a80d57cca3de5f3c2ad7ece704181858814713867ac57972ab67f9e05fe1a"
    "6a8a71d2237a9e4ac099c59911615c01f91cf20e77e6a77ffbe391e90e59d8d0"
    "0544f0c0686230054becf9281203ab3fc5f69cb30838cf50476faa5a511ce741"
    "96de9c85d8d93fa4f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a"
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d"
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83"
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e"
    "0716a3d62450d9835b28b226ae54754f99f8d10e4180371b02e976b51bc2312a"
    "eca4a5c0d12418f08402e746ce704181858814713867ac574d04d95233ebdb0f"
    "6a8a71d25b903867159d46a1b3a5950123329d230f0c01528c23dbd10e59d8d0"
    "a8aad5d5108896284becf92865c3e1071fd8f39ed216a07d9d41c577f3d82e41"
    "341a558575371ab1f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a"
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d"
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83"
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e"
    "0716a3d62450d9835b28b226af54754f9bf8d10ee044fe1bab0753a0cbc6b212"
    "474a80d57bca3de5fbc2ad7ec77041818f8814713367ac579b2ab67f9305fe1a"
    "648a71d22c7a9e4ad099c59900615c01eb1cf20e64e6a77fefe391e91b59d8d0"
    "1344f0c07f62300553ecf9280b03ab3fdff69cb31338cf505b6faa5a4c1ce741"
)

# Verified section layout (absolute file offsets, sizes in bytes).
KNOWN_LAYOUT = {
    "stringLiteral": (0x100, 45240 * 8),
    "stringLiteralData": (0x586C0, 0x13DE37),
    "string": (0x1964F8, 0x714FB4 - 0x1964F8),
    "events": (0x714FB4, 372 * 24),
    "properties": (0x717294, 35325 * 20),
    "methods": (0x7C3A58, 211214 * 36),
    "parameterDefaultValues": (0xF04050 + 4649 * 12, 54179 * 12),
    "fieldDefaultValues": (0xF04050, 4649 * 12),
    "fieldAndParameterDefaultValueData": (0xFB05E0, 0x1193AFC - 0xFB05E0),
    "fieldMarshaledSizes": (0, 0),
    "parameters": (0x1193AFC, 213031 * 12),
    "fields": (0x1403CD0, 166873 * 12),
    "genericParameters": (0x15ECAFC, 5725 * 16),
    "genericParameterConstraints": (0x16030CC, 1701 * 4),
    "genericContainers": (0x1604B60, 3453 * 16),
    "nestedTypes": (0x1612330, 9782 * 4),
    "interfaces": (0x161BC08, 0x6D5C),
    "vtableMethods": (0x1622964, 0x12D354),
    "interfaceOffsets": (0x174FCB8, 0x2EF58),
    "typeDefinitions": (0x177EC10, 28348 * 88),
    "images": (0x19DFCB0, 133 * 40),
    "assemblies": (0x19E1178, 133 * 64),
    "fieldRefs": (0x19E32B8, 1758 * 8),
    "referencedAssemblies": (0x19E69A8, 981 * 4),
    "attributeData": (0x19E78FC, 0x119E48),
    "attributeDataRange": (0x1B01744, 0x67A18),
    "unresolvedVirtualCallParameterTypes": (0x1B6915C, 0x11C00),
    "unresolvedVirtualCallParameterRanges": (0x1B7AD5C, 0xB608),
    "windowsRuntimeTypeNames": (0, 0),
    "windowsRuntimeStrings": (0, 0),
    "exportedTypeDefinitions": (0x1B86364, 0x3BDC),
}

VANILLA_ORDER = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties",
    "methods", "parameterDefaultValues", "fieldDefaultValues",
    "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
    "fields", "genericParameters", "genericParameterConstraints",
    "genericContainers", "nestedTypes", "interfaces", "vtableMethods",
    "interfaceOffsets", "typeDefinitions", "images", "assemblies",
    "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges", "windowsRuntimeTypeNames",
    "windowsRuntimeStrings", "exportedTypeDefinitions",
]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_OUT_OVERRIDE = None


def game_dir():
    """Locate the game root: APIIMO_GAME env var, else walk up from this
    script (and from cwd) until a directory containing GameAssembly.dll
    or Aniimo_Data is found."""
    env = os.environ.get("APIIMO_GAME")
    if env and os.path.exists(os.path.join(env, BINARY_REL)):
        return os.path.abspath(env)

    starts = []
    if globals().get("__file__"):
        starts.append(os.path.dirname(os.path.abspath(__file__)))
    starts.append(os.getcwd())

    for start in starts:
        d = os.path.abspath(start)
        for _ in range(6):
            if (os.path.exists(os.path.join(d, BINARY_REL))
                    or os.path.isdir(os.path.join(d, "Aniimo_Data"))):
                return d
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    return os.getcwd()


def meta_path(gd):
    return os.path.join(gd, METADATA_REL)


def bin_path(gd):
    return os.path.join(gd, BINARY_REL)


def out_path(gd):
    p = _OUT_OVERRIDE or os.path.join(gd, OUT_DIR)
    os.makedirs(p, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------


class PE:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        opt = pe + 24
        opt_size = struct.unpack_from("<H", d, pe + 20)[0]
        self.imagebase = struct.unpack_from("<Q", d, opt + 24)[0]
        so = opt + opt_size
        self.secs = []
        for i in range(nsec):
            o = so + i * 40
            vsize, va, rsize, raw = struct.unpack_from("<IIII", d, o + 8)
            self.secs.append((va, vsize, raw, rsize))

    def va2off(self, va):
        rva = va - self.imagebase
        for va0, vsize, raw, _ in self.secs:
            if va0 <= rva < va0 + vsize:
                return raw + rva - va0
        return None

    def off2va(self, off):
        for va0, vsize, raw, rsize in self.secs:
            if raw <= off < raw + rsize:
                return self.imagebase + va0 + off - raw
        return None

    def patch(self, va, hexbytes):
        off = self.va2off(va)
        if off is None:
            raise ValueError(f"VA {va:#x} not mapped")
        blob = bytes.fromhex(hexbytes.replace(" ", ""))
        d = bytearray(self.data)
        d[off:off + len(blob)] = blob
        open(self.path, "wb").write(bytes(d))
        self.data = bytes(d)
        return off


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------


def embedded_key():
    return np.frombuffer(bytes.fromhex(EMBEDDED_KEY_HEX), dtype=np.uint8)


def decrypt_body(c, K):
    """K is phase-aligned to file offset 256 (period 1152)."""
    body = c[256:]
    P = len(K)
    tile = np.tile(K, len(body) // P + 2)[256:256 + len(body)]
    return body ^ tile


def recover_key(c, P=KEY_PERIOD):
    """Statistical keystream recovery (slow fallback for new builds).

    Recovers a key aligned to offset 0; caller must re-align to 256.
    """
    from collections import Counter
    N = len(c)

    def decrypt(K):
        return c ^ np.tile(K, N // P + 1)[:N]

    K = np.zeros(P, dtype=np.uint8)
    for r in range(P):
        K[r] = np.bincount(c[r::P], minlength=256).argmax()
    K[0:4] = c[0:4] ^ np.frombuffer(SANITY.to_bytes(4, "little"), np.uint8)
    K[4:8] = c[4:8] ^ np.frombuffer(
        int(VERSION).to_bytes(4, "little"), np.uint8)
    dec = decrypt(K)

    printable = np.zeros(256, dtype=bool)
    printable[32:127] = True
    for _ in range(3):
        ok = np.zeros(N, dtype=bool)
        for i in range(0x60000, min(N, 0x740000), 0x1000):
            if printable[dec[i:i + 0x1000]].mean() > 0.6:
                ok[i:i + 0x1000] = True
        pos_all = np.flatnonzero(ok)
        if len(pos_all) == 0:
            break
        for r in range(P):
            sel = pos_all[pos_all % P == r]
            if len(sel) < 100:
                continue
            s = c[sel]
            scores = printable[s ^ np.arange(256)[:, None]].mean(axis=1)
            o = np.argsort(scores)[::-1]
            if scores[o[0]] > 0.9:
                K[r] = o[0]
        dec = decrypt(K)

    seg_a, seg_b = 0x70000, min(0x710000, N)
    seg = dec[seg_a:seg_b]
    idx = np.flatnonzero(printable[seg])
    runs = np.split(idx, np.flatnonzero(np.diff(idx) != 1) + 1)
    tg = Counter()
    for run in runs:
        if len(run) < 16:
            continue
        b3 = seg[run].astype(np.int64)
        tg.update(((b3[:-2] << 16) | (b3[1:-1] << 8) | b3[2:]).tolist())
    if tg:
        logp = np.full(1 << 24, np.log(1e-9))
        keys = np.array(sorted(tg), dtype=np.int64)
        vals = np.array([tg[k] for k in keys], dtype=np.float64)
        logp[keys] = np.log(vals / vals.sum())
        off3 = np.arange(-2, 3)
        for r in range(P):
            pos = np.arange(r, seg_b - 2, P)
            pos = pos[pos >= seg_a + 2]
            if len(pos) < 200:
                continue
            ctx = dec[pos[:, None] + off3]
            s = c[pos]

            def score(d):
                cc = ctx.copy()
                cc[:, 2] = d
                return (logp[(cc[:, 0].astype(np.int64) << 16)
                             | (cc[:, 1].astype(np.int64) << 8)
                             | cc[:, 2]].sum()
                        + logp[(cc[:, 1].astype(np.int64) << 16)
                               | (cc[:, 2].astype(np.int64) << 8)
                               | cc[:, 3]].sum()
                        + logp[(cc[:, 2].astype(np.int64) << 16)
                               | (cc[:, 3].astype(np.int64) << 8)
                               | cc[:, 4]].sum())

            best_kb, best_sc = int(K[r]), score(int(K[r]))
            for kb in range(256):
                if kb == int(K[r]):
                    continue
                d = s ^ kb
                if printable[d].mean() < 0.93:
                    continue
                sc2 = score(d)
                if sc2 > best_sc + 1.0:
                    best_sc, best_kb = sc2, kb
            K[r] = best_kb

    K[0:4] = c[0:4] ^ np.frombuffer(SANITY.to_bytes(4, "little"), np.uint8)
    K[4:8] = c[4:8] ^ np.frombuffer(
        int(VERSION).to_bytes(4, "little"), np.uint8)
    return K


# ---------------------------------------------------------------------------
# Default-value sanitization
# ---------------------------------------------------------------------------


def sanitize_defaults(meta, S, types_count=TYPES_IN_BINARY):
    """Neutralize fdv/pdv records the vanilla dumper cannot resolve:
    typeIndex >= typesCount (handle-based generic types) and dataIndex
    past the blob (or -1). They are pointed at a benign I4 type and a
    null blob offset so no image is lost to exceptions."""
    u32 = np.frombuffer(bytes(meta), dtype="<u4")
    fdo, fds = S["fieldDefaultValues"]
    pdo, pds = S["parameterDefaultValues"]
    blob_off, blob_size = S["fieldAndParameterDefaultValueData"]

    fdv = u32[fdo // 4:fdo // 4 + fds // 12 * 3].reshape(-1, 3)
    ok = fdv[(fdv[:, 1] < types_count) & (fdv[:, 2] < blob_size)]
    # In v31 builds (this game) ALL default-value typeIndices are metadata
    # handles >= typesCount, so `ok` is usually empty. 18204 is a verified
    # benign Il2CppType index for this binary.
    if len(ok):
        from collections import Counter
        safe_ti = int(Counter(ok[:, 1].tolist()).most_common(1)[0][0])
    else:
        safe_ti = 18204

    blob = meta[blob_off:blob_off + blob_size]
    null_off, run = 0, 0
    for j, b in enumerate(blob):
        if b == 0:
            run += 1
            if run >= 16:
                null_off = j - run + 1
                break
        else:
            run = 0

    fixed = 0
    for base, cnt in ((fdo, fds // 12), (pdo, pds // 12)):
        for r in range(cnt):
            o = base + r * 12
            ti = struct.unpack_from("<I", meta, o + 4)[0]
            di = struct.unpack_from("<I", meta, o + 8)[0]
            if ti >= types_count or di >= blob_size:
                meta[o + 4:o + 8] = struct.pack("<I", safe_ti)
                meta[o + 8:o + 12] = struct.pack("<I", null_off)
                fixed += 1
    return meta, fixed


# ---------------------------------------------------------------------------
# Dump pipeline
# ---------------------------------------------------------------------------


def build_header(S):
    hdr = bytearray()
    hdr += struct.pack("<I", SANITY)
    hdr += struct.pack("<i", VERSION)
    for name in VANILLA_ORDER:
        off, size = S.get(name, (0, 0))
        hdr += struct.pack("<II", off, size)
    assert len(hdr) == 256
    return bytes(hdr)


def cmd_dump(gd):
    mp = meta_path(gd)
    bp = bin_path(gd)
    op = out_path(gd)
    raw = np.fromfile(mp, dtype=np.uint8)
    if int.from_bytes(raw[:4].tobytes(), "little") != SANITY:
        sys.exit(f"{mp} does not look like an IL2CPP metadata file")
    ver = int.from_bytes(raw[4:8].tobytes(), "little")

    if ver == VERSION:
        print("[*] metadata already decrypted; using as-is")
        dec = raw
        S = KNOWN_LAYOUT
        dec_full = dec
    else:
        K = embedded_key()
        tile = np.tile(K, len(raw) // len(K) + 2)
        probe = raw[0x70000:0x70040] ^ tile[0x70000:0x70040]
        if ((probe >= 32) & (probe < 127)).mean() < 0.8:
            print("[!] embedded key mismatch -> statistical recovery")
            K0 = recover_key(raw)
            K = np.concatenate([K0[1152:1152 + 256], K0[256:1152]])
        body = decrypt_body(raw, K)
        dec_full = np.concatenate([np.zeros(256, np.uint8), body])
        dec = dec_full
        S = KNOWN_LAYOUT

    print("[1/3] verifying layout...")
    u32 = np.frombuffer(dec.tobytes(), dtype="<u4")
    to = S["typeDefinitions"][0] // 4 + 21
    tok_ok = (u32[to] >> 24) == 0x02 and (u32[to + 22] >> 24) == 0x02
    ev_ok = int(u32[S["events"][0] // 4 + 5]) >> 24 == 0x14
    if not (tok_ok and ev_ok):
        sys.exit("layout verification FAILED - build mismatch?")
    print(f"      typeDefinitions @ {S['typeDefinitions'][0]:#x}, "
          f"{S['typeDefinitions'][1] // 88} types - OK")

    print("[2/3] building header + sanitizing defaults...")
    hdr = build_header(S)
    meta = bytearray(hdr + dec[256:].tobytes())
    meta, fixed = sanitize_defaults(meta, S)
    print(f"      sanitized {fixed} default-value records")

    dec_path = os.path.join(op, DEC_NAME)
    open(dec_path, "wb").write(bytes(meta))
    print("[3/3] running Il2CppDumper...")
    r = subprocess.run(["il2cpp-dumper", bp, dec_path, op],
                       capture_output=True, text=True)
    open(os.path.join(op, "dumper.log"), "w").write(r.stdout + r.stderr)
    n_err = r.stdout.count("Some errors")
    print(f"      done ({n_err} per-image errors)")
    for f in ("dump.cs", "script.json", "il2cpp.h", "stringliteral.json"):
        p = os.path.join(op, f)
        if os.path.exists(p):
            print(f"      {f:24} {os.path.getsize(p):>12,} bytes")
    ndll = sum(len(fs) for _, _, fs in
               os.walk(os.path.join(op, "DummyDll")))
    print(f"      DummyDll assemblies:     {ndll}")


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def load_script(gd):
    p = os.path.join(out_path(gd), "script.json")
    if not os.path.exists(p):
        sys.exit("run `apiimo.py dump` first")
    return json.load(open(p))


def cmd_classes(gd, pattern, limit=100):
    rx = re.compile(pattern, re.IGNORECASE)
    p = os.path.join(out_path(gd), "dump.cs")
    ns = ""
    hits = 0
    for line in open(p, encoding="utf-8", errors="replace"):
        mns = re.match(r"^// Namespace: (.*)$", line)
        if mns:
            ns = mns.group(1).strip()
            continue
        m = re.search(r"(class|struct|interface) (\S+)"
                      r"(?: : ([^\r\n/]*))?", line)
        if m and not line.strip().startswith("//"):
            name = m.group(2)
            if rx.search(name) or rx.search(ns):
                ti = re.search(r"TypeDefIndex: (\d+)", line)
                print(f"{ns + '.' if ns else ''}{name}"
                      f"  [type {ti.group(1) if ti else '?'}]")
                hits += 1
                if hits >= limit:
                    return
    print(f"-- {hits} classes")


def cmd_methods(gd, pattern, limit=60):
    rx = re.compile(pattern, re.IGNORECASE)
    p = os.path.join(out_path(gd), "dump.cs")
    cls = ""
    hits = 0
    lines = open(p, encoding="utf-8", errors="replace").readlines()
    for i, line in enumerate(lines):
        mc = re.search(r"(class|struct) (\S+)", line)
        if mc and "// TypeDefIndex" in line:
            cls = mc.group(2)
            continue
        if "RVA:" in line and i + 1 < len(lines):
            sig = lines[i + 1].strip()
            if rx.search(sig) or rx.search(cls):
                mm = re.search(r"RVA: (0x[0-9A-Fa-f]+) Offset: "
                               r"(0x[0-9A-Fa-f]+) VA: (0x[0-9A-Fa-f]+)",
                               line)
                if mm:
                    print(f"{mm.group(3)}  {sig}")
                    hits += 1
                    if hits >= limit:
                        return
    print(f"-- {hits} methods")


def cmd_fields(gd, cls_pattern, limit=80):
    rx = re.compile(cls_pattern, re.IGNORECASE)
    p = os.path.join(out_path(gd), "dump.cs")
    lines = open(p, encoding="utf-8", errors="replace").readlines()
    show = False
    shown = 0
    for line in lines:
        mc = re.search(r"(class|struct) (\S+)", line)
        if mc and ("// TypeDefIndex" in line
                   or line.startswith(("public", "internal"))):
            show = bool(rx.search(mc.group(2)))
        if show:
            print(line.rstrip())
            shown += 1
            if shown >= limit:
                break


def cmd_addr(gd, spec):
    s = load_script(gd)
    lo = spec.lower()
    hits = [m for m in s["ScriptMethod"] if lo in m["Name"].lower()]
    for h in hits[:20]:
        print(f"{h['Address']:#x}  {h['Name']}")
    print(f"-- {len(hits)} methods")


def cmd_str(gd, pattern, limit=40):
    s = load_script(gd)
    rx = re.compile(pattern, re.IGNORECASE)
    n = 0
    for e in s["ScriptString"]:
        if rx.search(str(e.get("Value", ""))):
            print(f"{e['Address']:#x}  {e['Value']!r}")
            n += 1
            if n >= limit:
                return
    print(f"-- {n} literals")


def cmd_va2off(gd, va):
    print(hex(PE(bin_path(gd)).va2off(int(va, 16))))


def cmd_off2va(gd, off):
    print(hex(PE(bin_path(gd)).off2va(int(off, 16))))


def cmd_patch(gd, va, hexbytes):
    off = PE(bin_path(gd)).patch(int(va, 16), hexbytes)
    print(f"patched {len(hexbytes) // 2} bytes at file offset {off:#x}")


# ---------------------------------------------------------------------------
# Experimental: dynamic section rediscovery
# ---------------------------------------------------------------------------


def cmd_discover(gd):
    """Best-effort dynamic rediscovery (no embedded layout)."""
    raw = np.fromfile(meta_path(gd), dtype=np.uint8)
    K = embedded_key()
    body = decrypt_body(raw, K)
    dec_full = np.concatenate([np.zeros(256, np.uint8), body])
    u32 = np.frombuffer(dec_full.tobytes(), dtype="<u4")
    NW = len(u32)
    S = {}
    o = 0x100 // 4
    n, di = 0, 0
    while o + 1 < NW and int(u32[o]) <= 65536 and int(u32[o + 1]) == di:
        n += 1
        di += int(u32[o])
        o += 2
    S["stringLiteral"] = (0x100, n * 8)
    S["stringLiteralData"] = (0x100 + n * 8, di)
    for k in sorted(S):
        o, sz = S[k]
        print(f"  {k:42} [{o:#010x}, {o + sz:#010x}) {sz:#x}")
    print("  (experimental - full dynamic discovery is a work in progress; "
          "the embedded KNOWN_LAYOUT is used for `dump`)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    gd = os.environ.get(
        "APIIMO_GAME",
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if not os.path.exists(meta_path(gd)):
        gd = os.getcwd()
    args = sys.argv[1:]
    if "--out" in args:
        i = args.index("--out")
        globals()["_OUT_OVERRIDE"] = os.path.abspath(args[i + 1])
        del args[i:i + 2]
    if "--game" in args:
        i = args.index("--game")
        gd = os.path.abspath(args[i + 1])
        del args[i:i + 2]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    a = args[1:]
    if cmd == "dump":
        cmd_dump(gd)
    elif cmd == "discover":
        cmd_discover(gd)
    elif cmd == "classes" and a:
        cmd_classes(gd, a[0])
    elif cmd == "methods" and a:
        cmd_methods(gd, a[0])
    elif cmd == "fields" and a:
        cmd_fields(gd, a[0])
    elif cmd == "addr" and a:
        cmd_addr(gd, a[0])
    elif cmd == "str" and a:
        cmd_str(gd, a[0])
    elif cmd == "va2off" and a:
        cmd_va2off(gd, a[0])
    elif cmd == "off2va" and a:
        cmd_off2va(gd, a[0])
    elif cmd == "patch" and len(a) > 1:
        cmd_patch(gd, a[0], a[1])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
