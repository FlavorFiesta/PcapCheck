"""Old release data survives the PcapCheck identity migration."""
import sqlite3

from app.db import migrate_legacy_database


def test_legacy_database_is_backed_up_without_changing_source(tmp_path):
    old = tmp_path / "pcapdoctor.db"
    new = tmp_path / "pcapcheck.db"
    with sqlite3.connect(old) as conn:
        conn.execute("CREATE TABLE marker (value TEXT)")
        conn.execute("INSERT INTO marker VALUES ('preserved')")
    migrate_legacy_database(old, new)
    with sqlite3.connect(new) as conn:
        assert conn.execute("SELECT value FROM marker").fetchone()[0] == "preserved"
    with sqlite3.connect(old) as conn:
        assert conn.execute("SELECT value FROM marker").fetchone()[0] == "preserved"
    with sqlite3.connect(new) as conn:
        conn.execute("UPDATE marker SET value='new'")
    migrate_legacy_database(old, new)
    with sqlite3.connect(new) as conn:
        assert conn.execute("SELECT value FROM marker").fetchone()[0] == "new"
