#!/usr/bin/env python3
"""Writes KeePass XML with 1000 made-up entries for performance tests.

The content is deterministic: 10 groups of 100 entries, every tenth entry
with two history versions. Each current entry carries a CustomData item,
which only KDBX 4 supports, so keepassxc-cli writes KDBX 4.0. No real
secrets.

Usage: tools/kdbx-fixtures/gen-large-content.py > large.xml
"""

import base64
import random
from xml.sax.saxutils import escape

GROUPS = 10
ENTRIES_PER_GROUP = 100
TIMESTAMP = "2026-01-01T10:00:00Z"
WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
         "india", "juliett", "kilo", "lima", "mike", "november", "oscar", "papa"]

rng = random.Random(4711)


def uuid() -> str:
    return base64.b64encode(rng.randbytes(16)).decode()


def times(indent: str) -> str:
    return (f"{indent}<Times><LastModificationTime>{TIMESTAMP}</LastModificationTime>"
            f"<CreationTime>{TIMESTAMP}</CreationTime><LastAccessTime>{TIMESTAMP}</LastAccessTime>"
            f"<ExpiryTime>{TIMESTAMP}</ExpiryTime><Expires>False</Expires>"
            f"<UsageCount>0</UsageCount><LocationChanged>{TIMESTAMP}</LocationChanged></Times>\n")


def string(key: str, value: str, protected: bool = False) -> str:
    attribute = ' ProtectInMemory="True"' if protected else ""
    return f"<String><Key>{key}</Key><Value{attribute}>{escape(value)}</Value></String>"


def entry(entry_uuid: str, title: str, user: str, password: str, url: str, notes: str,
          history: str | None = None) -> str:
    # History versions are entries without a History element of their own.
    history_element = "" if history is None else f"\t\t\t\t\t<History>{history}</History>\n"
    return ("\t\t\t\t<Entry>\n"
            f"\t\t\t\t\t<UUID>{entry_uuid}</UUID><IconID>0</IconID>\n"
            + times("\t\t\t\t\t")
            + "\t\t\t\t\t" + string("Notes", notes) + string("Password", password, True)
            + string("Title", title) + string("URL", url) + string("UserName", user) + "\n"
            "\t\t\t\t\t<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0"
            "</DataTransferObfuscation><DefaultSequence/></AutoType>\n"
            + ("" if history is None else
               "\t\t\t\t\t<CustomData><Item><Key>SailVaultFixtureEntry</Key>"
               "<Value>large</Value></Item></CustomData>\n")
            + history_element
            + "\t\t\t\t</Entry>\n")


def main() -> None:
    groups = []
    number = 0
    for group_index in range(GROUPS):
        entries = []
        for _ in range(ENTRIES_PER_GROUP):
            number += 1
            words = rng.sample(WORDS, 2)
            title = f"{words[0].title()} {words[1]} {number:04d}"
            user = f"user{number:04d}@example.org"
            url = f"https://{words[0]}{number:04d}.example.org/login"
            notes = f"Made-up note for entry {number}.\nSecond line {words[1]}."
            entry_uuid = uuid()
            history = ""
            if number % 10 == 0:
                history = "".join(
                    entry(entry_uuid, title, user, f"old-{version}-{number:04d}", url, notes)
                    for version in (1, 2))
            entries.append(entry(entry_uuid, title, user, f"password-{number:04d}", url,
                                 notes, history))
        groups.append(
            "\t\t\t<Group>\n"
            f"\t\t\t\t<UUID>{uuid()}</UUID><Name>Group {group_index + 1:02d}</Name><IconID>48</IconID>\n"
            + times("\t\t\t\t")
            + "".join(entries)
            + "\t\t\t</Group>\n")

    print('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
          "<KeePassFile>\n\t<Meta>\n\t\t<Generator>SailVault large fixture</Generator>\n"
          "\t\t<DatabaseName>SailVault 1000 entries</DatabaseName>\n"
          "\t\t<CustomData><Item><Key>SailVaultFixtureMeta</Key><Value>large</Value></Item>"
          "</CustomData>\n\t</Meta>\n\t<Root>\n\t\t<Group>\n"
          f"\t\t\t<UUID>{uuid()}</UUID><Name>Root</Name><IconID>48</IconID>\n"
          + times("\t\t\t")
          + "".join(groups)
          + "\t\t</Group>\n\t</Root>\n</KeePassFile>")


if __name__ == "__main__":
    main()
