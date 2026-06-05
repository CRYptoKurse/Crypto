import sqlite3
conn = sqlite3.connect('pki/micropki.db')
cur = conn.cursor()
cur.execute('SELECT serial_hex, status, revocation_reason FROM certificates WHERE subject LIKE "%compromise_me%"')
for row in cur.fetchall():
    print(row)
conn.close()
