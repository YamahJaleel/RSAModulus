import mysql.connector
import logging

# Global flag and fallback store for users
db_available = True
fallback_user_store = {}

# Predefine these variables so they're always available
mydb = None
mycursor = None

# Try connecting to the MySQL database; if it fails, use fallback storage.
try:
    mydb = mysql.connector.connect(
        host="",
        user="",
        password="",
        database=""
    )
    mycursor = mydb.cursor()
    logging.info("Database connection established.")
except Exception as e:
    logging.error("Failed to connect to the database: %s", e)
    db_available = False
    fallback_user_store = {}  # In-memory dictionary for user data
    logging.info("Using fallback in-memory user store.")
