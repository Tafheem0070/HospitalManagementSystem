import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    config = {
        "host": os.getenv("DB_HOST"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "database": os.getenv("DB_NAME"),
        "connection_timeout": 10,
    }

    # TiDB Cloud requires TLS.
    # Use the CA certificate locally when available.
    if os.path.exists("ca.pem"):
        config["ssl_ca"] = "ca.pem"

    return mysql.connector.connect(**config)


if __name__ == "__main__":
    try:
        connection = get_db_connection()
        print("✅ MySQL/TiDB connection successful!")
        connection.close()
    except mysql.connector.Error as error:
        print("❌ Database connection failed:")
        print(error)