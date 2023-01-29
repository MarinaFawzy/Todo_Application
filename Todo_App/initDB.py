from db import get_db, close_db
import sqlite3


def create_tables():
    try:
        connection = get_db()
        connection.execute("""
                            CREATE TABLE User (
                            User_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Email   TEXT UNIQUE NOT NULL,
                            Username TEXT UNIQUE NOT NULL,
                            Password TEXT NOT NULL,
                            phoneNumber Text NOT NULL
                            );
                            """)

        connection.execute("""
                            CREATE TABLE Admin (
                            User_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Email   TEXT UNIQUE NOT NULL,
                            Username TEXT UNIQUE NOT NULL,
                            Password TEXT NOT NULL,
                            phoneNumber Text NOT NULL
                            );
                            """)

        connection.execute("""
                            CREATE TABLE Task (
                            Task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Title   TEXT UNIQUE NOT NULL,
                            Describtion TEXT UNIQUE NOT NULL,
                            Status TEXT  ,
                            User_id INTEGER ,
                            
                            );
                            """)
        connection.commit()
        close_db(connection)

    except Exception as err:
        print("Error")


create_tables()
