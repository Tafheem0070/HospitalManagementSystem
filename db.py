import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        port=3306,
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        connection_timeout=10
    )


if __name__ == "__main__":
    try:
        connection = get_db_connection()
        print("✅ MySQL connection successful!")
        connection.close()
    except mysql.connector.Error as error:
        print("❌ MySQL connection failed:")
        print(error)