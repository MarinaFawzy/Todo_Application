import check
import os
from flask import Flask, request, redirect, url_for, flash, render_template,send_file,abort
from flask_mail import Mail, Message
# g is available across the request context
from flask import session, g
# Data base functions
from db import *
# Strong Hashing function SHA256
from werkzeug.security import check_password_hash, generate_password_hash
# Save image with secured name
from werkzeug.utils import secure_filename
# Generate OTP in random way
import random
# Calculating the blocked time and when to remove the block
from datetime import datetime, timedelta
# Handling many requests to avoid brute force attack 
from flask_limiter import Limiter
# get current IP Address or 127.0.0.1 for local host
from flask_limiter.util import get_remote_address


app = Flask(__name__)
# app.run(debug=False)

# Used to sign session cookies for protection against cookie data tampering and used in encryption
app.secret_key = 'CyberSecuritySecretKey'

# A01
def is_safe_path(requested_path):
    # Safe path (Server Side)
    safe_path = 'files/Safe/'
    # get the absolute path
    safe_path = os.path.realpath(safe_path)
    # Compare the absolute path with the sent path if it safe it will return true (See the common Prefix)
    return os.path.commonprefix((os.path.realpath(requested_path),safe_path)) == safe_path

# A02
# Vigenre Encryption & Decryption 
def Encryption_Vigenre(message, key):
    key_int = [ord(i) for i in key]
    message_int = [ord(i) for i in message]
    encrypted_message = ''

    for i in range(len(message_int)):
        letters = key_int[i % len(key)]
        encrypted_letters = (message_int[i] - 32 + letters) % 95
        encrypted_message += chr(encrypted_letters + 32)
    return encrypted_message

def Decryption_Vigenere(message, key):
    key_int = [ord(i) for i in key]
    message_int = [ord(i) for i in message]
    decrypted_message = ''

    for i in range(len(message_int)):
        letters = key_int[i % len(key)]
        decrypted_letters = (message_int[i] - 32 - letters) % 95
        decrypted_message += chr(decrypted_letters + 32)
    return decrypted_message

# A04
# Handle more than wrong OTP (More than false request) to avoid Brute force attack
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# A05 
# Setting Image valid extensions, size and the local storage to save the image
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024 #3MB Existing Class Var
app.config['IMAGE_EXTENSIONS'] = ['.png', '.jpeg', '.jpg']
app.config['UPLOAD_DIR'] = 'static/uploadedImgs'

# A07
# Setting Image the email and password to send the OTP from 
app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "todowebapplication0@gmail.com"
app.config["MAIL_PASSWORD"] = "chloycepksclhtff" 
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
# Run the mail library
mail = Mail(app)
# Generate OTP
otp = random.randint(100000,999999)


# a function runs before dealing with any request
@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        all_users = retreive_users()
        # a list pull anything matches the condition inside the bracket
        # 0 if it unique return it directly 
        user = [x for x in all_users if x['User_id'] == session['user_id']][0]
        g.user = user

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/signUp/", methods=['GET', 'POST'])
def signUp():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            phoneNumber = request.form['phoneNumber']
            # Hashing the password to before saving it in the DB
            hash_password = generate_password_hash(password)
            insert_user(email, username, hash_password,phoneNumber)
            return redirect(url_for('login'))
        except Exception as err:
            flash("Something went wrong!!!")
            return render_template('sign-up.html')
    return render_template('sign-Up.html')

@app.route("/Login/", methods=['GET', 'POST'])
def login():
    # Clear any admin access if exist
    if 'email' in session:
        session.clear()
    if request.method == 'POST':
        try:            
            email = request.form['email']
            password = request.form['password']

            all_users = retreive_users()
            user = [x for x in all_users if x['Email'] == email][0]

            # A04
            if 'blocked' in session:
                # If the user block time is finished
                print("Here")
                delta = (datetime.now() - datetime.strptime(session['blocked'],"%Y-%m-%d %H:%M:%S.%f")).total_seconds()
                print(delta)
                if delta > 60 * 2:
                    session.clear()
            if 'blocked' in session: 
                # If the user block time is not finished yet
                print("here")
                delta = (datetime.now() - datetime.strptime(session['blocked'],"%Y-%m-%d %H:%M:%S.%f")).total_seconds()
                if delta < 60 * 2:
                    time = session['blocked']
                    time = 2 - int(delta)//60
                    flash(f"You are blocked, wait for {time} minute/s and try again")
                    return render_template('login.html')
            # Checking user credentials 
            elif (user and check_password_hash(user['Password'], password)):
                # If Admin 
                if (email in check.admins): 
                    #A 01
                    session.clear()
                    session['admin'] = True
                    session['email'] = email
                    return redirect(url_for('admin'))
                # If User
                else:
                    # A06
                    # Generating OTP Message and send it to the user for 2FA 
                    msg = Message(subject="OTP", sender="todowebapplication0@gmail.com", recipients=[email])
                    msg.body = str(otp)
                    mail.send(msg)
                    session["userEmail"] = email
                    return redirect(url_for('getOTP'))
            else:
                # A04
                # If the Password/Email wrong start a session with the date of (first false attempt)
                if 'blockTime' not in session:
                    session['blockTime'] = str(datetime.now())
                # More attempt in less than one minute
                if (datetime.now() - datetime.strptime(session['blockTime'],"%Y-%m-%d %H:%M:%S.%f")).total_seconds() < 60:
                    if 'loginAttempts' not in session:
                        session['loginAttempts'] = 3
                    if session['loginAttempts'] > 0:
                        session['loginAttempts'] -= 1
                        if session['loginAttempts'] != 0:
                            flash(f"Wrong password, you still have {session['loginAttempts']} attempts remaining")
                    if session['loginAttempts'] == 0:
                        # Calculate the time of block 
                        session['blocked'] = str(datetime.now())
                        # Calculate the time to remove the bock 
                        blockedTime = datetime.now() + timedelta(minutes=2)
                        flash(f"You are blocked, please try again at {blockedTime.time().hour}:{blockedTime.time().minute}")
                else:
                    # More than 1 min -> Clear session and login again
                    session.clear()
                return(render_template('login.html'))
        except Exception as err:
            print(err)
            flash("Something went wrong.")
    # if the method == 'GET'
    return render_template('login.html')

# A06
@app.route("/getOTP/", methods=['GET',"POST"])
# If the user entered 10 times wrong OTP per Minute -> redirect to login page and clear session and generate new OTP
@limiter.limit("10 per minute")
def getOTP():
    # Check if the user already passed the login or not
    if 'userEmail' not in session:
        flash('You Must Login First')
        return render_template('login.html')
    try:
        all_users = retreive_users()
        user = [x for x in all_users if x['Email'] == session["userEmail"]][0]

        if request.method == 'POST':
            # Take the OTP from the user
            userOTP = request.form['otp']
            # Compare the entered OTP to the generated OTP
            if otp == int(userOTP):
                session['user_id'] = user['User_id']
                return redirect(url_for('home'))
    except Exception as err:
        print(err)
        flash("Wrong OTP")
        return redirect(url_for("getOTP"))
    return render_template('validateOTP.html')

# A06
# Handling More than 10 wrong OTP / Minute
@app.errorhandler(429)
def ratelimit_handler(e):
    session.clear()
    flash(f'Please login again')
    return redirect(url_for('login'))

# A01
@app.route("/admin/")
def admin():
    # Check if the admin logged in or not 
    if 'admin' not in session:
        session.clear()
        flash("Something went wrong, please login first!!")
        return redirect(url_for("login"))
    all_users = retreive_users()
    return render_template("admin.html",user = all_users)

# A01
@app.route("/download/<path:file_path>")
def download(file_path):
    if 'admin' not in session:
        flash("Something went wrong, please login first!")
        return redirect(url_for("login"))
    # file = "files/safe/test.txt"
    # Check the Path (passed by the HTML in admin.html)
    if is_safe_path(file_path):
        return send_file(file_path,as_attachment=True)
    else:
        return abort(401)

# Handel path traversal attack (Unauthorized Path)
@app.errorhandler(401)
def unauth_handler(e):
    session.clear()
    flash(f'You are not authorized to this path!')
    return redirect(url_for('login'))

@app.route("/Home/", methods=['GET', 'POST'])
def home():
    # if there is no sessions
    if not g.user or 'userEmail' not in session:
        flash("Please, Login first!")
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route("/secreteNote", methods=["GET","POST"])
def secreteNote():
    if request.method == 'POST':
        card = request.form['card']
        csv = request.form['csv']
        expire = request.form['expire']
        amount = request.form['amount']

        card = Encryption_Vigenre(card,app.secret_key)
        csv = Encryption_Vigenre(csv,app.secret_key)
        expire = Encryption_Vigenre(expire,app.secret_key)
        print(card)
        print(csv)
        print(expire)

        # Check
        print(Decryption_Vigenere(card,app.secret_key))
    return render_template("secreteNote.html")


@app.route("/addTask/", methods=['GET', 'POST'])
def addTask():
    if not g.user:
        flash("Something went wrong, please login first!")
        return redirect(url_for("login"))
    if request.method == 'POST':
        try:
            title = request.form['title']
            description = request.form['description']
            # Take the image as a file
            file = request.files['file']
            # Insert Task (Image inserted locally)
            insert_Task(title, description, g.user['User_id'])
            
            # Split the file to (name,extension) => [0] for name and [1] extension
            fileExtension = os.path.splitext(file.filename)[1] #Extension
            # Check that the extension is in the valid extensions
            if fileExtension in app.config['IMAGE_EXTENSIONS']:
                # Save the file in secured way (No Spaces) and in the determined location in the config
                file.save(os.path.join(
                    app.config['UPLOAD_DIR'],
                    secure_filename(file.filename)
                ))
                return redirect(url_for('viewTasks'))
            if fileExtension == "":
                return redirect(url_for('viewTasks'))
            if fileExtension not in app.config['IMAGE_EXTENSIONS']:
                # Not an image
                raise Exception
        except Exception as err:
            # Not an image or more than 3MB
            print(err)
            flash("Please upload an Image within 3MB")
            return render_template('addTask.html')
    return render_template('addTask.html')


@app.route("/viewTasks/", methods=['GET', 'POST'])
def viewTasks():
    if not g.user:
        flash("Something went wrong, please login first!")
        return redirect(url_for("login"))
    try:
        if request.method == "POST":
            # Take the search and search with it in the DB
            title = request.form['search']
            tasks = retrieve_task(g.user['User_id'],title)
            return render_template('viewTasks.html', tasks=tasks)
    except Exception as err:
        # Not logged in
        flash("Something went wrong")
        print(err)
        session.clear()
        return render_template('login.html')
    return render_template('viewTasks.html')

@app.route("/updateTask/<int:id>", methods=['GET', 'POST'])
def updateTask(id=None):
    if not g.user:
        flash("Something went wrong, please login first!")
        return redirect(url_for("login"))
    if request.method == "POST":
        taskTitle = request.form['title']
        description = request.form['description']
        status = request.form['status']
        update_task(taskTitle,description,status,id)
        return redirect(url_for('viewTasks'))
    flash("Something went wrong!")
    return redirect(url_for('home'))

@app.route("/deleteTask/<int:id>", methods=['GET', 'POST'])
def deleteTask(id=None):
    if not g.user:
        flash("Something went wrong, please login first!")
        return redirect(url_for("login"))
    return redirect(url_for('viewTasks'))

@app.route("/deleteUser/<int:id>", methods=['GET', 'POST'])
def deleteUser(id=None):
    delete_user(id)
    return redirect(url_for('admin'))

@app.route("/logout", methods=['GET', 'POST'])
def logout():
    try:
        session.pop("user_id")
        session.pop("admin")
        session.pop('userEmail')
        session.clear()
        return redirect(url_for('login'))
    except Exception as err:
        # flash("Something went wrong11")
        print(err)
        return render_template('index.html')