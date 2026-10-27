#!/usr/bin/env python3
"""
fritzdecode.py - decrypt AVM FRITZ!Box configuration exports (.export files).

Python port of the Rust crate `fritzdecode` by Xiretza
(https://gitlab.com/xiretza/fritzdecode, AGPL-3.0-or-later).

What it does:
  * parses the export (header, properties, CFGFILE/B64FILE sections)
  * derives the key from your export password and decrypts every $$$$... secret
  * recalculates the CRC so the result is a valid export again
  * optionally verifies the original CRC and/or extracts every file to a folder

Requirements:  pip install pycryptodome      (or: pip install cryptography)

Usage:
  python fritzdecode.py backup.export -p MyPassword -o decrypted.export
  python fritzdecode.py backup.export -p MyPassword --extract out_dir
  python fritzdecode.py backup.export --check        # only verify the CRC
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import re
import sys
import zlib
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# AES-256-CBC (no padding) - works with either pycryptodome or cryptography
# --------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES as _AES  # pycryptodome

    def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)

except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return d.update(data) + d.finalize()

    except ImportError:
        sys.exit("Need an AES library: pip install pycryptodome  (or: pip install cryptography)")


class FritzError(Exception):
    pass


# --------------------------------------------------------------------------
# Fritz base32: RFC 4648 alphabet, but digits 1-6 instead of 2-7, no padding
# --------------------------------------------------------------------------
_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
_B32_LOOKUP = {c: i for i, c in enumerate(_B32_ALPHABET)}


def fritz_b32decode(s: str) -> bytes:
    out = bytearray()
    buf = 0
    bits = 0
    for ch in s:
        try:
            v = _B32_LOOKUP[ch]
        except KeyError:
            raise FritzError(f"invalid base32 character {ch!r}")
        buf = (buf << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


# --------------------------------------------------------------------------
# Crypto
# --------------------------------------------------------------------------
def bootstrap_key(password: str) -> bytes:
    """MD5 of the export password, zero-padded to 32 bytes."""
    return hashlib.md5(password.encode("utf-8")).digest().ljust(32, b"\0")


def decode_secret(secret: str, key: bytes, is_string: bool) -> bytes:
    if not secret.startswith("$$$$"):
        raise FritzError(f"secret has no $$$$ prefix: {secret[:20]}...")
    raw = fritz_b32decode(secret[4:])

    # strip excess bytes introduced by base32 rounding
    extra = len(raw) % 16
    if extra > 4:
        raise FritzError(f"bad ciphertext length (excess {extra} bytes)")
    if extra:
        raw = raw[:-extra]
    if len(raw) < 32:
        raise FritzError("ciphertext too short")

    iv, ciphertext = raw[:16], raw[16:]
    plain = aes256_cbc_decrypt(key, iv, ciphertext)

    # layout: 4 bytes md5 prefix | 4 bytes BE length | data | zero padding
    checksum, rest = plain[:4], plain[4:]
    if hashlib.md5(rest).digest()[:4] != checksum:
        raise FritzError("hash mismatch - wrong password?")

    length = int.from_bytes(rest[:4], "big")
    data = rest[4 : 4 + length]
    if is_string:
        if not data.endswith(b"\0"):
            raise FritzError("decrypted string has no null terminator")
        data = data[:-1]
    return data


def decrypt_encryption_key(encrypted_key: str, bkey: bytes) -> bytes:
    key = decode_secret(encrypted_key, bkey, is_string=False)
    if len(key) != 32:
        raise FritzError(f"decrypted encryption key has length {len(key)}, expected 32")
    return key[:16] + b"\0" * 16


_SECRET_RE = re.compile(r"\${4}[A-Z1-6]+")


def decode_secrets_in_text(text: str, key: bytes) -> tuple[str, int]:
    count = 0

    def repl(m: re.Match) -> str:
        nonlocal count
        count += 1
        data = decode_secret(m.group(0), key, is_string=True)
        return data.decode("utf-8", errors="surrogateescape")

    return _SECRET_RE.sub(repl, text), count


# --------------------------------------------------------------------------
# Export file model
# --------------------------------------------------------------------------
def _enc(s: str) -> bytes:
    return s.encode("utf-8", errors="surrogateescape")


@dataclass
class FileEntry:
    name: str
    binary: bool
    text: str = ""          # for CFGFILE (each line terminated by \n)
    data: bytes = b""       # for B64FILE


@dataclass
class ConfigBackup:
    model: str
    properties: list[tuple[str, str]] = field(default_factory=list)
    files: list[FileEntry] = field(default_factory=list)
    crc: int = 0

    # ---- parsing ----
    @classmethod
    def load(cls, raw: bytes) -> "ConfigBackup":
        text = raw.decode("utf-8", errors="surrogateescape")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        lines = [l[:-1] if l.endswith("\r") else l for l in lines]
        it = iter(enumerate(lines, 1))

        def nxt(what: str):
            try:
                return next(it)
            except StopIteration:
                raise FritzError(f"unexpected end of file, expected {what}")

        n, header = nxt("header")
        suffix = " CONFIGURATION EXPORT"
        if not (header.startswith("**** ") and header.endswith(suffix)):
            raise FritzError(f"line {n}: not a FRITZ!Box export header: {header!r}")
        cfg = cls(model=header[5 : -len(suffix)])

        # properties until first "**** " line
        n, line = nxt("property or file section")
        while not line.startswith("**** "):
            if "=" not in line:
                raise FritzError(f"line {n}: expected KEY=VALUE property, got {line!r}")
            k, v = line.split("=", 1)
            cfg.properties.append((k, v))
            n, line = nxt("property or file section")

        # files until END OF EXPORT
        while True:
            m = re.fullmatch(r"\*\*\*\* END OF EXPORT ([0-9A-Fa-f]{8}) \*\*\*\*", line)
            if m:
                cfg.crc = int(m.group(1), 16)
                break
            if line.startswith("**** CFGFILE:"):
                entry = FileEntry(line[len("**** CFGFILE:"):], binary=False)
            elif line.startswith("**** B64FILE:"):
                entry = FileEntry(line[len("**** B64FILE:"):], binary=True)
            else:
                raise FritzError(f"line {n}: expected file section, got {line!r}")

            text_parts: list[str] = []
            bin_parts: list[bytes] = []
            while True:
                n, line = nxt("END OF FILE")
                if line.startswith("**** "):
                    if line != "**** END OF FILE ****":
                        raise FritzError(f"line {n}: expected END OF FILE, got {line!r}")
                    break
                if entry.binary:
                    try:
                        bin_parts.append(base64.b64decode(line, validate=True))
                    except Exception as e:
                        raise FritzError(f"line {n}: invalid base64 in {entry.name}: {e}")
                else:
                    text_parts.append(line.replace("\\\\", "\\") + "\n")
            entry.text = "".join(text_parts)
            entry.data = b"".join(bin_parts)
            cfg.files.append(entry)
            n, line = nxt("file section or END OF EXPORT")
        return cfg

    # ---- CRC ----
    def calculate_crc(self) -> int:
        crc = 0
        for k, v in self.properties:
            crc = zlib.crc32(_enc(k) + _enc(v) + b"\0", crc)
        for f in self.files:
            crc = zlib.crc32(_enc(f.name) + b"\0", crc)
            if f.binary:
                crc = zlib.crc32(f.data, crc)
            else:
                # everything up to (not including) the last newline
                idx = f.text.rfind("\n")
                if idx != -1:
                    crc = zlib.crc32(_enc(f.text[:idx]), crc)
        return crc & 0xFFFFFFFF

    # ---- decryption ----
    def decrypt(self, password: str) -> int:
        enc_key_prop = next((v for k, v in self.properties if k == "Password"), None)
        if enc_key_prop is None:
            raise FritzError("no 'Password=' property in header - export not encrypted?")
        try:
            key = decrypt_encryption_key(enc_key_prop, bootstrap_key(password))
        except FritzError as e:
            raise FritzError(f"could not unlock the export key - wrong password? ({e})")
        total = 0
        for f in self.files:
            if not f.binary:
                f.text, n = decode_secrets_in_text(f.text, key)
                total += n
        return total

    # ---- output ----
    def serialize(self) -> bytes:
        out: list[str] = [f"**** {self.model} CONFIGURATION EXPORT\n"]
        out += [f"{k}={v}\n" for k, v in self.properties]
        for f in self.files:
            if f.binary:
                out.append(f"**** B64FILE:{f.name}\n")
                if not f.data:
                    out.append("\n")
                for i in range(0, len(f.data), 60):
                    out.append(base64.b64encode(f.data[i : i + 60]).decode() + "\n")
            else:
                out.append(f"**** CFGFILE:{f.name}\n")
                out.append(f.text.replace("\\", "\\\\"))
            out.append("**** END OF FILE ****\n")
        out.append(f"**** END OF EXPORT {self.crc:08X} ****\n")
        return _enc("".join(out))

    def extract(self, directory: str) -> None:
        os.makedirs(directory, exist_ok=True)
        for f in self.files:
            safe = f.name.replace("/", "_").replace("\\", "_") or "unnamed"
            path = os.path.join(directory, safe)
            with open(path, "wb") as fh:
                fh.write(f.data if f.binary else _enc(f.text))


# --------------------------------------------------------------------------
# Self-test with the known vectors from the Rust crate
# --------------------------------------------------------------------------
def _selftest() -> None:
    cases = [
        (b"test", "$$$$5AEWFTDNEIXGOGVTKJYBXJ2JK1B1LDDUXDLOAQPSQTPGI6LCQRLP1E5DEPNJIF45F4ADNFTXZF31541T",
         "7695206a0422786fc612643ed2f337d900000000000000000000000000000000"),
        (b"testus", "$$$$4ZNKDABPVOF32CDHBPIGXRGUOPWFS3KYOUXXZK61GQ6TT1E4JYYUDOE6YMLBML6ZOJSO53NGG3HOS4ZY",
         "3cfb14830234eb5abf8de7570d47d79600000000000000000000000000000000"),
        (b"testuse", "$$$$UEUST1NGXTC1Y52R2CSML4TNJPT2HV54MGFUXRCYHH3ROBT3OMBLV66ZQ2XOGZURJTRTP3123QQB34Y5",
         "4b50c9683664a466c117d89986ef5c9300000000000000000000000000000000"),
        (b"testuser", "$$$$XLSJ6KVR2KNNBUVJHBA1NPMDEZCHZI4GAMY3BMNUJ5CN4PAGLKWD5K5M5GJYBXKBF1BJE5JX5GEFA4W5",
         "19d1c0f994c4a7157a99363d8d60097500000000000000000000000000000000"),
    ]
    assert fritz_b32decode("KRSXG4BAMRQXIYJB") == b"Test data!"
    for plain, secret, key in cases:
        got = decode_secret(secret, bytes.fromhex(key), is_string=True)
        assert got == plain, (got, plain)
    print("self-test OK")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Decrypt a FRITZ!Box configuration export.")
    ap.add_argument("input", nargs="?", help="the .export file")
    ap.add_argument("-p", "--password", help="password used when exporting (prompted if omitted)")
    ap.add_argument("-o", "--output", help="write decrypted export here (default: <input>.decrypted.export)")
    ap.add_argument("--extract", metavar="DIR", help="also write every contained file into DIR")
    ap.add_argument("--check", action="store_true", help="only verify the CRC, don't decrypt")
    ap.add_argument("--ignore-crc", action="store_true", help="continue even if the original CRC is wrong")
    ap.add_argument("--selftest", action="store_true", help="run built-in test vectors and exit")
    args = ap.parse_args()

    if args.selftest:
        _selftest()
        return
    if not args.input:
        ap.error("input file required")

    try:
        with open(args.input, "rb") as fh:
            cfg = ConfigBackup.load(fh.read())
        print(f"Model: {cfg.model}   files: {len(cfg.files)}   properties: {len(cfg.properties)}")

        calc = cfg.calculate_crc()
        crc_ok = calc == cfg.crc
        print(f"CRC in file: {cfg.crc:08X}   calculated: {calc:08X}   -> {'OK' if crc_ok else 'MISMATCH'}")
        if args.check:
            sys.exit(0 if crc_ok else 1)
        if not crc_ok and not args.ignore_crc:
            raise FritzError("CRC mismatch - the file is damaged or was edited. "
                             "Re-run with --ignore-crc to decrypt anyway.")

        password = args.password if args.password is not None else getpass.getpass("Export password: ")
        n = cfg.decrypt(password)
        cfg.crc = cfg.calculate_crc()
        print(f"Decrypted {n} secret(s). New CRC: {cfg.crc:08X}")

        out = args.output or os.path.splitext(args.input)[0] + ".decrypted.export"
        with open(out, "wb") as fh:
            fh.write(cfg.serialize())
        print(f"Wrote {out}")

        if args.extract:
            cfg.extract(args.extract)
            print(f"Extracted {len(cfg.files)} file(s) to {args.extract}/")
    except FritzError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
