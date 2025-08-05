"""
Flask App for:           Lab 6 - CYOP 300
Revised and appended for Lab 7 - CYOP 300
Revised and appended for Lab 8 - CYOP 300
Written by Rob Culbertson
"""
import ast
import os
import re
from datetime import datetime
import flask
from flask import render_template, request, redirect, url_for
from passlib.hash import sha256_crypt

app = flask.Flask(__name__)

# --- Routes ---
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
    return render_template('dog.html', name=name_up, time=fm_now, date=fm_now_date)
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    This processes the form submission and redirects to a dynamic URL
    """
    if request.method == 'POST':
        # Use .get() to prevent crashing on missing form fields
        username = request.form.get('Username', '').strip()
        password = request.form.get('password', '').strip()

        users = load_users()

        # Check if the username exists in our loaded data
        if username not in users:
            log_failed_attempt(username)
            return render_template('user_not_found.html')

        # Verify the password against the stored hash
        stored_hash_pass = users[username]
        if sha256_crypt.verify(password, stored_hash_pass):
            return render_template('dog.html', name=username)
        else:
            log_failed_attempt(username)
            return render_template('login_error.html')
    return redirect(url_for('index'))
@app.route('/register', methods=['GET', 'POST'])
def registration():
    """
    Registers the user and saves credentials to file.
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Check if the password meets complexity and NIST requirements
        is_valid, message = pass_check(password)
        if not is_valid:
            return render_template('re_register_password_complexity.html', error=message)

        # Load all users to check for a duplicate username
        users = load_users()
        if username.lower() in (u.lower() for u in users.keys()):
            return render_template('re_register_username.html', error='Username already registered')

        # If all checks pass, hash the password and save the new user
        pass_hash = sha256_crypt.hash(password)
        users[username] = pass_hash
        save_users(users)

        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/update', methods=['GET', 'POST'])
def update_password():
    """
    Updates the user password and saves credentials to file.
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        old_password = request.form.get('old_password', '').strip()
        updated_password = request.form.get('new_password', '').strip()
        pass_confirm = request.form.get('password_confirm', '').strip()

        # Load all users from the file
        users = load_users()

        # Check if the user exists
        if username not in users:
            return render_template('user_not_found.html')

        # Verify the old password and confirm the new one
        if not sha256_crypt.verify(old_password, users[username]):
            return render_template('update_error.html', error="Incorrect old password.")
        if updated_password != pass_confirm:
            return render_template('update_error.html', error="New passwords do not match.")

        # Check if the new password meets complexity and NIST requirements
        is_valid, message = pass_check(updated_password)
        if not is_valid:
            return render_template('re_register_password_complexity.html', error=message)

        # Hash the new password and update the dictionary
        new_pass_hash = sha256_crypt.hash(updated_password)
        users[username] = new_pass_hash

        # Save the updated data back to the file
        save_users(users)

        return render_template('update_success.html')

    return render_template('update_password.html')
# --- Helper Functions ---
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
    if not nist(password):
        return False, "Selected password is too common, please select a different password."
    return True, "Password meets requirements"
def nist(password):
    """
    Checks the given password against the commonly used password document provided
    :param password: password for comparison
    :return: boolean response on if the password passes the nist requirements.
    """
    with open('CommonPassword.txt', 'r') as file:
        common_passwords = {line.strip() for line in file}
        if password.strip() in common_passwords:
            return False
        else:
            return True

def log_failed_attempt(username: str):
    """
    Logs a failed login attempt to a file.
    Includes timestamp, username, and remote IP address.
    """
    log_file_path = "failed_logins.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Get the remote IP address of the client
    ip_address = request.remote_addr if request.remote_addr else "UNKNOWN_IP"

    log_entry = f"[{timestamp}] Failed login for user: '{username}' from IP: {ip_address}\n"

    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(log_entry)
    except IOError as e:
        print(f"Error writing to log file {log_file_path}: {e}")

# --- File I/O Functions ---
def load_users(file_path='users.txt'):
    """
    Reads user data from the text file.
    Returns a dictionary mapping usernames to hashed passwords.
    Returns an empty dictionary if the file does not exist.
    """
    users = {}
    if not os.path.exists(file_path):
        return users

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                username, pass_hash = ast.literal_eval(line)
                users[username] = pass_hash
            except (ValueError, SyntaxError) as e:
                print(f"Warning: Malformed line in users.txt: {line} - Error: {e}")
    return users

def save_users(users, file_path='users.txt'):
    """
    Saves the user data from a dictionary back to the text file.
    This function overwrites the entire file.
    """
    with open(file_path, 'w') as file:
        for username, pass_hash in users.items():
            user_tuple = (username, pass_hash)
            file.write(str(user_tuple) + '\n')

if __name__ == '__main__':
    app.run()
