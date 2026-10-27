#!/usr/bin/env python3
"""
fritzphonebook.py - convert the raw `phonebook` file from a FRITZ!Box config
export into the phonebook XML format the FRITZ!Box can import
(Telefonie > Telefonbuch > Wiederherstellen).

The raw file (e.g. from `fritzdecode.py backup.export --extract out_dir`) is not
valid XML on its own:
  * its XML declaration is broken (`<?xml version=... encoding=...>`)
  * it has no single root element; it holds several <phonebook> blocks plus
    <featureflags>, <uniqueid> and <settings>
  * it contains the internal phonebook (owner="255"), which lists the box's
    internal numbers (broadcast, answering machine, DECT handsets, alarms).
    The FRITZ!Box rebuilds that phonebook itself, so it is skipped by default.

The output looks like this:
  <?xml version="1.0" encoding="utf-8"?>
  <phonebooks>
  <phonebook>...contacts...</phonebook>
  </phonebooks>

Usage:
  python fritzphonebook.py phonebook                 # -> phonebook.xml
  python fritzphonebook.py phonebook -o Telefonbuch.xml
  python fritzphonebook.py phonebook --list          # show the phonebooks found
  python fritzphonebook.py phonebook --book 0        # only phonebook #0
  python fritzphonebook.py phonebook --include-internal

If the raw file contains several regular phonebooks, each one is written to its
own file (<output>_<index>.xml), because the FRITZ!Box imports one phonebook at
a time.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

INTERNAL_OWNER = "255"


def load_raw(path: str) -> ET.Element:
    with open(path, "rb") as fh:
        text = fh.read().decode("utf-8")
    # drop the (possibly broken) XML declaration
    text = re.sub(r"^\s*<\?xml.*?\??>", "", text, count=1, flags=re.DOTALL)
    try:
        return ET.fromstring(f"<root>{text}</root>")
    except ET.ParseError as e:
        sys.exit(f"Error: could not parse {path}: {e}")


def describe(book: ET.Element) -> str:
    contacts = book.findall("contact")
    owner = book.get("owner")
    name = book.get("name")
    label = "internal" if owner == INTERNAL_OWNER else "regular"
    extra = f', name="{name}"' if name else ""
    owner_s = f", owner={owner}" if owner is not None else ""
    return f"{label}{owner_s}{extra}: {len(contacts)} contacts"


def to_import_xml(book: ET.Element) -> bytes:
    # FRITZ!Box exports have no owner attribute; keep a name if there is one
    out = ET.Element("phonebook")
    if book.get("name"):
        out.set("name", book.get("name"))
    for contact in book.findall("contact"):
        out.append(contact)
    body = ET.tostring(out, encoding="unicode")
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            f"<phonebooks>\n{body}\n</phonebooks>\n").encode("utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Convert a raw FRITZ!Box phonebook file into importable XML.")
    ap.add_argument("input", help="raw `phonebook` file extracted from the config export")
    ap.add_argument("-o", "--output", help="output file (default: <input>.xml)")
    ap.add_argument("--list", action="store_true", help="only list the phonebooks found")
    ap.add_argument("--book", type=int, action="append",
                    help="index of a phonebook to convert (see --list); can be repeated")
    ap.add_argument("--include-internal", action="store_true",
                    help="also convert the internal phonebook (owner=255)")
    args = ap.parse_args()

    root = load_raw(args.input)
    books = root.findall("phonebook")
    if not books:
        sys.exit("Error: no <phonebook> found in the file")

    if args.list:
        for i, b in enumerate(books):
            print(f"[{i}] {describe(b)}")
        return

    if args.book:
        bad = [i for i in args.book if not 0 <= i < len(books)]
        if bad:
            sys.exit(f"Error: no phonebook with index {bad[0]} (use --list)")
        selected = [(i, books[i]) for i in args.book]
    else:
        selected = [(i, b) for i, b in enumerate(books)
                    if args.include_internal or b.get("owner") != INTERNAL_OWNER]
    if not selected:
        sys.exit("Error: nothing to convert (only the internal phonebook was found; "
                 "use --include-internal)")

    base = args.output or os.path.splitext(args.input)[0] + ".xml"
    stem, ext = os.path.splitext(base)
    for i, book in selected:
        path = base if len(selected) == 1 else f"{stem}_{i}{ext or '.xml'}"
        with open(path, "wb") as fh:
            fh.write(to_import_xml(book))
        print(f"[{i}] {describe(book)} -> {path}")


if __name__ == "__main__":
    main()
