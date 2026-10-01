import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "package", "lib"))
sys.path.insert(0, os.path.join(ROOT, "package", "bin"))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def make_autoblock_db(path, rows):
    """rows: (IP, RecordTime, ExpireTime, Deny, IPStd, Type)"""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE AutoBlockIP(IP varchar(50) PRIMARY KEY, RecordTime date NOT NULL,"
                " ExpireTime date NOT NULL, Deny boolean NOT NULL, IPStd varchar(50) NOT NULL,"
                " Type INTEGER, Meta varchar(256))")
    con.executemany("INSERT INTO AutoBlockIP VALUES (?, ?, ?, ?, ?, ?, NULL)", rows)
    con.commit()
    con.close()


def make_connlog_db(path, rows):
    """rows: (utcsec, msg). Mirrors the logs table layout of .SYNOCONNDB."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, utcsec INTEGER,"
                " tag TEXT, level TEXT, username TEXT, msg TEXT)")
    con.executemany("INSERT INTO logs(utcsec, tag, level, username, msg)"
                    " VALUES (?, 'conn', 'info', NULL, ?)", rows)
    con.commit()
    con.close()
