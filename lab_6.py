"""
Flask App for Lab 6 - CYOP 300
Written by Rob Culbertson
"""

from datetime import datetime
import flask
from flask import render_template, request, redirect, url_for

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

@app.route('/process_name', methods=['POST'])
def process_name():
    """
    This processes the form submission and redirects to a dynamic URL
    """
    if request.method == 'POST':
        name=request.form['name'].strip()
        # Redirects the url to the dynamic entry of the user
        return redirect(url_for('dog', name=name))
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
