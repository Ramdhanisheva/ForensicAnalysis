"""
Automotion Forensics - Database & Browser Storage Inspector
Analyzes SQLite databases (.db, .sqlite, .sqlite3), Firefox/Chrome history,
and carves unallocated/deleted records from raw database pages.
"""

import os
import re
import sqlite3
from typing import Any, Dict, List, Optional

from core.string_hunter import StringHunter


class DBInspector:
    """Inspects SQLite databases, extracts table contents, browser history, and unallocated slack strings."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def is_sqlite(self, header_bytes: bytes) -> bool:
        """Check for SQLite format 3 magic bytes."""
        return header_bytes.startswith(b"SQLite format 3\x00")

    def inspect_database(self, filepath: str) -> Dict[str, Any]:
        """
        Deep SQLite inspection:
        - Schema & Table enumeration
        - Search all text columns for flags and credentials
        - Browser history & cookie extraction
        - Raw slack space carving for deleted records
        """
        results: Dict[str, Any] = {
            "source": filepath,
            "format": "SQLite Database v3",
            "is_valid_db": False,
            "tables": [],
            "row_counts": {},
            "browser_history": [],
            "browser_cookies": [],
            "flags_found": [],
            "credentials": [],
            "deleted_record_hints": []
        }

        if not os.path.exists(filepath):
            results["error"] = "File not found"
            return results

        # 1. First verify magic bytes
        try:
            with open(filepath, "rb") as f:
                header = f.read(16)
                if not self.is_sqlite(header):
                    results["error"] = "Not a valid SQLite v3 header"
                    return results
            results["is_valid_db"] = True
        except Exception as e:
            results["error"] = f"Header read error: {e}"
            return results

        # 2. Query Database Tables & Columns via read-only SQLite connection
        try:
            db_uri = f"file:{os.path.abspath(filepath)}?mode=ro"
            conn = sqlite3.connect(db_uri, uri=True)
            cursor = conn.cursor()

            # Enumerate tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
            table_rows = cursor.fetchall()
            tables = [r[0] for r in table_rows if not r[0].startswith("sqlite_stat")]
            results["tables"] = tables

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM \"{table}\";")
                    cnt = cursor.fetchone()[0]
                    results["row_counts"][table] = cnt

                    # Read up to 200 rows per table to avoid hanging on massive tables
                    cursor.execute(f"SELECT * FROM \"{table}\" LIMIT 200;")
                    rows = cursor.fetchall()
                    for row in rows:
                        row_str = " | ".join(str(val) for val in row if val is not None)
                        # Hunt flags in row text
                        flags = self.string_hunter.hunt_flags(row_str)
                        for fl in flags:
                            fl["context"] = f"[{table}] {fl['context']}"
                            results["flags_found"].append(fl)

                        # Check credentials in row
                        if any(k in row_str.lower() for k in ("password", "passwd", "secret", "token", "api_key")):
                            results["credentials"].append(f"[{table}] {row_str[:120]}")
                except Exception:
                    pass

            # 3. Check for Browser Specific Tables
            # Firefox places.sqlite (moz_places)
            if "moz_places" in tables:
                try:
                    cursor.execute("SELECT url, title, visit_count FROM moz_places ORDER BY visit_count DESC LIMIT 50;")
                    for u, t, vc in cursor.fetchall():
                        entry = f"{u} ({t or 'No Title'}) [Visits: {vc}]"
                        results["browser_history"].append(entry)
                        for fl in self.string_hunter.hunt_flags(entry):
                            fl["context"] = f"[Firefox History] {fl['context']}"
                            results["flags_found"].append(fl)
                except Exception:
                    pass

            # Chrome History (urls)
            if "urls" in tables:
                try:
                    cursor.execute("SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 50;")
                    for u, t, vc in cursor.fetchall():
                        entry = f"{u} ({t or 'No Title'}) [Visits: {vc}]"
                        results["browser_history"].append(entry)
                        for fl in self.string_hunter.hunt_flags(entry):
                            fl["context"] = f"[Chrome History] {fl['context']}"
                            results["flags_found"].append(fl)
                except Exception:
                    pass

            # Cookies (moz_cookies or cookies)
            cookie_table = "moz_cookies" if "moz_cookies" in tables else "cookies" if "cookies" in tables else None
            if cookie_table:
                try:
                    cursor.execute(f"SELECT host, name, value FROM \"{cookie_table}\" LIMIT 50;")
                    for h, n, v in cursor.fetchall():
                        results["browser_cookies"].append(f"{h} -> {n}={v[:40]}")
                        for fl in self.string_hunter.hunt_flags(f"{n}={v}"):
                            fl["context"] = f"[Cookie {h}] {fl['context']}"
                            results["flags_found"].append(fl)
                except Exception:
                    pass

            conn.close()

        except Exception as e:
            results["sqlite_query_error"] = str(e)

        # 4. Check for diff/edit history table reconstruction (Google CTF 2017)
        diff_res = self.reconstruct_diff_history(filepath)
        if diff_res.get("diff_table_found"):
            results["diff_history"] = diff_res
            for fl in diff_res.get("intermediate_flags", []):
                if not any(f["flag"] == fl["flag"] for f in results["flags_found"]):
                    results["flags_found"].append(fl)

        # 5. Raw Slack Space Carving for Deleted Records
        # When SQLite deletes a row, the text remains in unallocated B-Tree page slack space
        try:
            with open(filepath, "rb") as f:
                raw_db = f.read(20 * 1024 * 1024)  # Scan up to 20MB raw
            slack_flags = self.string_hunter.hunt_flags(raw_db)
            for fl in slack_flags:
                fl["encoding"] = f"SQLite Raw/Slack ({fl['encoding']})"
                if not any(f["flag"] == fl["flag"] for f in results["flags_found"]):
                    results["flags_found"].append(fl)
        except Exception:
            pass

        return results

    def reconstruct_diff_history(self, filepath: str) -> Dict[str, Any]:
        """
        SQLite Edit History Reconstruction from Diff Tables (Google CTF 2017 pattern):
        - Detects tables storing incremental diffs (type/operation, position, text)
        - Replays all operations sequentially ('insert', 'remove')
        - Hunts for flags at EVERY intermediate state (catching flags typed and then deleted)
        """
        results: Dict[str, Any] = {
            "diff_table_found": False,
            "table_name": None,
            "step_count": 0,
            "intermediate_flags": [],
            "final_document_preview": ""
        }

        if not os.path.exists(filepath):
            return results

        try:
            db_uri = f"file:{os.path.abspath(filepath)}?mode=ro"
            conn = sqlite3.connect(db_uri, uri=True)
            cursor = conn.cursor()

            # Enumerate tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]

            target_table = None
            target_cols = None

            # Look for diff/history table
            for tbl in tables:
                cursor.execute(f"PRAGMA table_info(\"{tbl}\");")
                cols = {c[1].lower(): c[1] for c in cursor.fetchall()}
                
                # Check for operation/type, position, text columns
                op_col = next((cols[k] for k in cols if k in ("type", "op", "operation", "action")), None)
                pos_col = next((cols[k] for k in cols if k in ("position", "pos", "offset", "idx")), None)
                text_col = next((cols[k] for k in cols if k in ("text", "data", "val", "value", "content")), None)

                if op_col and pos_col and text_col:
                    target_table = tbl
                    target_cols = (op_col, pos_col, text_col)
                    break

            if not target_table:
                conn.close()
                return results

            results["diff_table_found"] = True
            results["table_name"] = target_table

            op_c, pos_c, txt_c = target_cols
            # Order by id / rowid if available
            cursor.execute(f"SELECT \"{op_c}\", \"{pos_c}\", \"{txt_c}\" FROM \"{target_table}\" ORDER BY rowid ASC;")
            rows = cursor.fetchall()
            results["step_count"] = len(rows)

            document = ""
            for step_idx, (op_val, pos_val, txt_val) in enumerate(rows):
                op_str = str(op_val).lower().strip()
                try:
                    pos = int(pos_val)
                except Exception:
                    pos = len(document)
                text = str(txt_val) if txt_val is not None else ""

                if op_str in ("insert", "add", "+"):
                    document = document[:pos] + text + document[pos:]
                elif op_str in ("remove", "delete", "del", "-"):
                    document = document[:pos] + document[pos + len(text):]

                # Check for flags in this intermediate state
                flags = self.string_hunter.hunt_flags(document)
                for fl in flags:
                    fl["context"] = f"[{target_table} step #{step_idx} ({op_str})] {fl['context']}"
                    fl["encoding"] = f"SQLite Diff History ({fl['encoding']})"
                    if not any(f["flag"] == fl["flag"] for f in results["intermediate_flags"]):
                        results["intermediate_flags"].append(fl)

            results["final_document_preview"] = document[:200]
            conn.close()

        except Exception as e:
            results["error"] = str(e)

        return results
