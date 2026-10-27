# fritzdecode-py

Decrypt AVM FRITZ!Box configuration exports (`.export` files) with Python.

Port of the Rust crate [fritzdecode](https://gitlab.com/xiretza/fritzdecode) by Xiretza.

## What it does

- Parses the export: the header, the properties, and the `CFGFILE`/`B64FILE` sections
- Derives the key from the export password and decrypts every `$$$$…` secret
- Recalculates the CRC so the output is a valid export again
- Can verify the CRC of the original file and extract all contained files

## Setup

```
pip install pycryptodome      # or: pip install cryptography
```

## Usage

```
python fritzdecode.py backup.export -p YourExportPassword
python fritzdecode.py backup.export -p YourExportPassword --extract out_dir
python fritzdecode.py backup.export --check
python fritzdecode.py --selftest
```

- If `-p` is omitted, the script prompts for the password.
- The default output is `<input>.decrypted.export`. Use `-o` to change it.
- `--check` only verifies the CRC. A CRC mismatch is a common reason a FRITZ!Box refuses a backup.

## Limitations

- Only works for exports created **with a password**. Without one, the key is device-specific.
- Whether a different model or firmware accepts the decrypted export depends on AVM.

## License

AGPL-3.0-or-later, the same license as the original Rust crate.
