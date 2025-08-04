"""
Flask App for Lab 6 - CYOP 300
Revised and appended for Lab 7 - CYOP 300
Written by Rob Culbertson
"""
import ast
import re
from datetime import datetime
import flask, passlib
from flask import render_template, request, redirect, url_for
from matplotlib.style.core import update_nested_dict
from passlib.hash import sha256_crypt

app = flask.Flask(__name__)
@app.route('/')
def index():
    """
    index landing page
    """
    return flask.render_template('index.html')
@app.route('/<name>')
def dog(name):
    """
    Pulls datetime and personalizes the landing page for the name entered
    :param name: User's name
    """
    now = datetime.now()
    fm_now = now.strftime("%H:%M:%S")
    fm_now_date = now.strftime("%d/%m/%Y")
    name_up = name.capitalize()
    return render_template('dog.html', name=name_up, time = fm_now, date=fm_now_date)

@app.route('/login', methods=['GET','POST'])
def login():
    """
    This processes the form submission and redirects to a dynamic URL
    """
    if request.method == 'POST':
        username=request.form['Username'].strip()
        password=request.form['password'].strip()
        pass_hash = sha256_crypt.hash(password)

        with open('users.txt', 'r') as file:
            try:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        stored_username, stored_hash_pass = ast.literal_eval(line)
                        if username == stored_username or username.lower() == stored_username.lower():
                            if sha256_crypt.verify(password, stored_hash_pass):
                                    return render_template('dog.html', name=username)
                            return render_template('login_error.html')
                        return render_template('user_not_found.html')
                    except (ValueError, SyntaxError) as e:
                        print("Warning: Error encountered", e)
            except FileNotFoundError:
                print("User Data File Not Found")
            except IOError as e:
                print(f"Error reading from file {e}")
    return redirect(url_for('index'))
@app.route('/register', methods=['GET', 'POST'])
def registration():
    """
    Registers the user and saves credentials to file.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if pass_check(password):
            pass_hash = sha256_crypt.hash(password)
            user_data = (username, pass_hash)

            with open('users.txt', 'r') as file:
                # Rejects duplicate usernames
                try:
                    for line in file:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            #Converting the string tuple back into a python tuple for evaluation
                            stored_username, stored_hash_pass = ast.literal_eval(line)

                            #non case-sensitive username
                            if username == stored_username or username.lower() == stored_username.lower():
                                return render_template('re_register_username.html', error='Username already registered')
                        except (ValueError, SyntaxError) as e:
                            print("Warning: Error encountered", e)
                except FileNotFoundError:
                    print("User Data File Not Found")
                except IOError as e:
                    print(f"Error reading from file {e}")
                with open('users.txt', 'a') as file:
                    file.write(str(user_data) + '\n')
                    return redirect(url_for('index'))
        # If the password that was input does not meet the requirements - user will need to re-register using the appropriate error page redirect.
        return render_template('re_register_password_complexity.html', error='Password does not meet complexity requirements')
    #If the method is not a post request -> just render the registration page
    return render_template('register.html')
@app.route('/update', methods=['GET', 'POST'])
def update_password():
    """
    Updates the user password and saves credentials to file.
    """
    if request.method == 'POST':
        old_password = request.form['old_password']
        updated_password = request.form['updated_password']
        pass_confirm = request.form['password_confirm']

        with open('users.txt', 'r') as file:
            try:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                try:
                    stored_username, stored_password = ast.literal_eval(line)
                    if sha256_crypt.verify(old_password, stored_password) and pass_confirm == updated_password:
                        with open('users.txt', 'a') as f:

# def pass_processing():
def pass_check(password):
    """Checks to ensure minimum security requirements for password"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        return False, "Password must contain at least one special character."

    return True, "Password meets requirements"

if __name__ == '__main__':
    app.run()
