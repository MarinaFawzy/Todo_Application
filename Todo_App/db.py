from multiprocessing import connection
import sqlite3


def get_db():

    db = sqlite3.connect('TodoDB.sqlite',
                        detect_types=sqlite3.PARSE_DECLTYPES
                        )

    db.row_factory = sqlite3.Row
    return db


def close_db(db=None):
    if db is not None:
        db.close()


def retreive_users():
    connection = get_db().cursor()
    connection.execute("select * from User;")
    data = connection.fetchall()
    close_db(connection)
    return data

def retreive_admins():
    connection = get_db().cursor()
    connection.execute("select * from Admin;")
    data = connection.fetchall()
    close_db(connection)
    return data



def insert_user(email, name, h_pass, phoneNumber):
    connection = get_db()
    # connection.execute(f"""Insert into User (Email, Username, Password, phoneNumber) values("{email}", "{name}", "{h_pass}", "{phoneNumber}")""")
    connection.execute("""Insert into User (Email, Username, Password, phoneNumber) values(:email, :name, :h_pass, :phoneNumber)""",
    {'email':email, 'name': name, 'h_pass':h_pass, 'phoneNumber':phoneNumber})
    connection.commit()
    close_db(connection)


def retreive_tasks(id):
    connection = get_db().cursor()
    # connection.execute(f"select * from Task WHERE  User_id={id} ")
    connection.execute("""select * from Task WHERE  User_id=:id""",{'id':id})
    data = connection.fetchall()
    close_db(connection)
    return data

def retrieve_task(id,title):
    connection = get_db().cursor()
    # connection.execute(f"select * from Task WHERE  User_id={id} ")
    connection.execute("""select * from Task WHERE  User_id= :id and Title = :title""",{'id':id, 'title':title})
    data = connection.fetchall()
    close_db(connection)
    return data


def insert_Task(title, descr, id):
    connection = get_db()
    connection.execute("""Insert into Task (Title, Describtion, status, User_id) values(:title , :desc , 'Not Done', :id)""",{'title': title, 'desc': descr, 'id': id})
    connection.commit()
    close_db(connection)

def update_task(title,descr,status,id):
    connection = get_db()
    connection.execute("""UPDATE Task SET Title=:title, Describtion=:desc, status= :status WHERE Task_id=:tid ;""",{'title':title,'desc':descr,'status':status,'tid':id})
    connection.commit()
    close_db(connection)

def retreive_task(id,userID):
    connection = get_db().cursor()
    connection.execute("""select * from Task WHERE task_id= :tid and User_id = :usrID""",{'tid':id,'usrID':userID})
    data = connection.fetchone()
    close_db(connection)
    return data

def delete_task(id, userID):
    connection = get_db()
    connection.execute(f"Delete from Task WHERE task_id= :tid and User_id= :usrID",{'tid':id,'usrID':userID})
    connection.commit()
    close_db(connection)

def delete_user(id):
    connection = get_db()
    connection.execute("""Delete from User WHERE User_id= :id""",{'id':id})
    connection.commit()
    close_db(connection)

def retrieve_email(id):
    connection = get_db().cursor()
    connection.execute("""SELECT Email from User WHERE User_id=:id""",{'id':id})
    email = connection.fetchall()
    close_db(connection)
    return email

