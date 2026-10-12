import sqlite3
from datetime import datetime

DATABASE_NAME = "scam_history.db"


def create_database():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL,
            analysis_time TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_history(message, prediction, confidence):
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    analysis_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

    cursor.execute("""
        INSERT INTO detection_history
        (message, prediction, confidence, analysis_time)
        VALUES (?, ?, ?, ?)
    """, (message, prediction, confidence, analysis_time))

    connection.commit()
    connection.close()


def get_history():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT message, prediction, confidence, analysis_time
        FROM detection_history
        ORDER BY id DESC
    """)

    history = cursor.fetchall()

    connection.close()

    return history
	
	
	
	
	
	# Get detection statistics
def get_statistics():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            COUNT(*),
            SUM(CASE WHEN prediction = 'Spam' THEN 1 ELSE 0 END),
            SUM(CASE WHEN prediction = 'Legitimate' THEN 1 ELSE 0 END)
        FROM detection_history
    """)

    result = cursor.fetchone()
    connection.close()

    total = result[0] or 0
    spam = result[1] or 0
    legitimate = result[2] or 0

    spam_percentage = spam / total * 100 if total > 0 else 0

    return total, spam, legitimate, spam_percentage