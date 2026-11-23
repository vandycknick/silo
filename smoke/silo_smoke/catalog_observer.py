"""Short-lived, read-only SQLite observer, independent of the product runtime."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys


def observe(db: Path) -> dict[str, list[tuple[str, ...]]]:
    connection = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("BEGIN")
        schema = connection.execute("SELECT quote(type),quote(name),quote(tbl_name),quote(sql) FROM sqlite_schema ORDER BY type,name").fetchall()
        result = {"schema": schema}
        tables = connection.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").fetchall()
        for (table,) in tables:
            identifier = '"' + table.replace('"', '""') + '"'
            columns = connection.execute(f"PRAGMA table_info({identifier})").fetchall()
            names = ['"' + column[1].replace('"', '""') + '"' for column in columns]
            expressions = [f"typeof({name}) || ':' || hex({name})" for name in names]
            result[table] = sorted(connection.execute(f"SELECT {','.join(expressions)} FROM {identifier}").fetchall())
        return result
    finally:
        connection.close()


if __name__ == "__main__":
    json.dump(observe(Path(sys.argv[1])), sys.stdout)
