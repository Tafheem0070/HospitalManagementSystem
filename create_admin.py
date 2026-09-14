from db import get_db_connection
from werkzeug.security import generate_password_hash
import getpass

username = input("Enter admin username: ").strip()
password = getpass.getpass("Enter admin password: ")

password_hash = generate_password_hash(password)

connection = get_db_connection()
cursor = connection.cursor()

cursor.execute(
    """
    INSERT INTO users
    (account_id, username, password_hash, role)
    VALUES (%s, %s, %s, %s)
    """,
    ("ADM001", username, password_hash, "admin")
)

connection.commit()

cursor.close()
connection.close()

print("Admin account created successfully!")
print("Account ID: ADM001")
print("Username:", username)