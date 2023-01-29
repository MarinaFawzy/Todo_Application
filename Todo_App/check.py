# import sqlite3

username = ''
loginBtn = True
blocked = []
attempts = 3

isAdmin = False

admins = ["mox0600@gmail.com"]

email = ''
password = ''

def isLoggedIn():
    return not(username == '')

def removeBlocked():
    if blocked == None:
        return True
    else:
        blocked['email'] = ''
        blocked['time'] = ''

encrypt = ''

print(encrypt)

blockedTime = 0
