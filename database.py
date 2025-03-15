import mysql.connector

def get_connection():
    connection = mysql.connector.connect(
        host="localhost",
        port=3306,
        user="root",
        password="nX1c]atIv_[Y0c1_V1",
        database="user_database"
    )
    return connection