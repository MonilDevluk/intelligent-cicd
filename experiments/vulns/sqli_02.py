import sqlite3

def get_user_by_email(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = '%s'" % email
    cursor.execute(query)
    return cursor.fetchall()

def delete_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    conn.commit()
