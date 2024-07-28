
import os
import sqlite3


def connect_to_db():

    home_dir = os.path.expanduser("~")
    if os.name == "posix":  # Linux and MacOS
        db_file = os.path.join(home_dir, "certReport", "certReport.db")
    elif os.name == "nt":  # Windows
        db_file = os.path.join(home_dir, "certReport", "certReport.db")
    else:
        raise OSError("Unsupported operating system")

    # Create the directory if it does not exist
    db_dir = os.path.dirname(db_file)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    # Create the database file if it does not exist
    if not os.path.exists(db_file):
        db = sqlite3.connect(db_file)
        db.close()

    # Connect to the database
    db = sqlite3.connect(db_file)
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            SHA256_HASH TEXT,
            USER_SUPPLIED_TAG TEXT,
            CERTIFICATE_SUBJECT TEXT,
            ISSUER_SIMPLE_NAME TEXT,
            CERTIFICATE_ISSUER TEXT,
            CERTIFICATE_SERIAL TEXT,
            CERTIFICATE_THUMBPRINT TEXT,
            CERTIFICATE_VALID_FROM TEXT,
            CERTIFICATE_VALID_TO TEXT,
            CERTIFICATE_TAGS TEXT,
            SERVICE TEXT
            )
        ''')
    return db, cursor

def insert_into_db(database, cursor, SHA256_HASH, USER_SUPPLIED_TAG, CERTIFICATE_SUBJECT, CERTIFICATE_ISSUER, ISSUER_SIMPLE_NAME, CERTIFICATE_SERIAL, CERTIFICATE_THUMBPRINT, CERTIFICATE_VALID_FROM, CERTIFICATE_VALID_TO, CERTIFICATE_TAGS, SERVICE):
    cursor.execute('SELECT COUNT(*) FROM certificates WHERE SHA256_HASH = ?', (SHA256_HASH,))
    count = cursor.fetchone()[0]
    if count == 0:
        cursor.execute('''
            INSERT INTO certificates(SHA256_HASH, USER_SUPPLIED_TAG, CERTIFICATE_SUBJECT, CERTIFICATE_ISSUER, ISSUER_SIMPLE_NAME, CERTIFICATE_SERIAL, CERTIFICATE_THUMBPRINT, CERTIFICATE_VALID_FROM, CERTIFICATE_VALID_TO, CERTIFICATE_TAGS, SERVICE)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (SHA256_HASH, USER_SUPPLIED_TAG, CERTIFICATE_SUBJECT, CERTIFICATE_ISSUER, ISSUER_SIMPLE_NAME, CERTIFICATE_SERIAL, CERTIFICATE_THUMBPRINT, CERTIFICATE_VALID_FROM, CERTIFICATE_VALID_TO, CERTIFICATE_TAGS, SERVICE))
        database.commit()
    else:
        cursor.execute('DELETE FROM certificates WHERE SHA256_HASH = ?', (SHA256_HASH,))
        database.commit()
        cursor.execute('''
            INSERT INTO certificates(SHA256_HASH, USER_SUPPLIED_TAG, CERTIFICATE_SUBJECT, CERTIFICATE_ISSUER, ISSUER_SIMPLE_NAME, CERTIFICATE_SERIAL, CERTIFICATE_THUMBPRINT, CERTIFICATE_VALID_FROM, CERTIFICATE_VALID_TO, CERTIFICATE_TAGS, SERVICE)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (SHA256_HASH, USER_SUPPLIED_TAG, CERTIFICATE_SUBJECT, CERTIFICATE_ISSUER, ISSUER_SIMPLE_NAME, CERTIFICATE_SERIAL, CERTIFICATE_THUMBPRINT, CERTIFICATE_VALID_FROM, CERTIFICATE_VALID_TO, CERTIFICATE_TAGS, SERVICE))
        database.commit()


def close_db(db):
    db.close()

def check_previous_entry(cursor, SHA256_HASH):
    cursor.execute('''
        SELECT * FROM certificates WHERE SHA256_HASH = ?
        ''', (SHA256_HASH,))
    return cursor.fetchone()


def summarize_entries_by_tag(cursor, USER_SUPPLIED_TAG):
    cursor.execute('''
        SELECT ISSUER_SIMPLE_NAME, COUNT(ISSUER_SIMPLE_NAME) AS num_entries
        FROM certificates
        WHERE USER_SUPPLIED_TAG = ?
        GROUP BY ISSUER_SIMPLE_NAME
        ''', (USER_SUPPLIED_TAG,))
    return cursor.fetchall()