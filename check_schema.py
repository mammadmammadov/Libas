import sqlite3
db = sqlite3.connect('wardrobe.db')
rows = db.execute("SELECT sql FROM sqlite_master WHERE type='table'").fetchall()
for r in rows:
    if r[0]:
        print(r[0])
        print()
