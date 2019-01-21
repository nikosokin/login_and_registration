from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "secretkey"

emailFormat = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
nameFormat = re.compile(r'^[a-zA-Z]$')
passwordFormat = re.compile(r'^.*(?=.{8,15})(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$') #taken from StackOverflow

@app.route('/')
def index():
    mysql = connectToMySQL('mydb')
    print(mysql.query_db("SELECT * FROM people;"))
    return render_template('index.html')

@app.route('/register', methods = ['POST'])
def register():

    mysql = connectToMySQL('mydb')
    query = "SELECT * FROM people WHERE email = '%s';" % (request.form['email'])
    validInfo = True

    if mysql.query_db(query):
        flash("email already exists")
        validInfo = False
    if len(request.form['first_name']) < 2 or nameFormat.match(request.form['last_name']):
        flash("first name")
        validInfo = False
    if len(request.form['last_name']) < 2 or nameFormat.match(request.form['last_name']):
        flash("last name")
        validInfo = False
    if not emailFormat.match(request.form['email']):
        flash("email")
        validInfo = False
    if not passwordFormat.match(request.form['pw1']):
        flash("password")
        validInfo = False
    
    hashPW = bcrypt.generate_password_hash(request.form['pw1'])

    if not bcrypt.check_password_hash(hashPW, request.form['pw2']):
        flash("don't match")
        validInfo = False
    
    if validInfo == True:

        data = {

            "fn" : request.form['first_name'],
            "ln" : request.form['last_name'],
            "em" : request.form['email'],
            "ph" : hashPW
            
        }

        mysql = connectToMySQL('mydb')

        query = "INSERT INTO people (first_name, last_name, email, password_hash, created_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(ph)s, now());"

        session['current_id'] = mysql.query_db(query, data)
        
        flash("You are registered.")

        return redirect('/')
    
    if validInfo == False:

        return redirect('/')

@app.route('/login', methods = ['POST'])
def login():

    mysql = connectToMySQL('mydb')
    query = "SELECT * FROM people WHERE email = '%s';" % (request.form['email'])
    maybeId = mysql.query_db(query)
    
    print(maybeId)
    if not maybeId:
        flash("doesn't exist")
        return redirect('/')
    
    else:
        mysql = connectToMySQL('mydb')
        query = "SELECT password_hash FROM people WHERE email = '%s';" % (request.form['email'])
        pw_hash = mysql.query_db(query)
        print(pw_hash)

        if bcrypt.check_password_hash(pw_hash[0]['password_hash'], request.form['password']):
            mysql = connectToMySQL('mydb')
            query = "SELECT id FROM people WHERE email = '%s';" % (request.form['email'])
            session['current_id'] = mysql.query_db(query)
            return render_template('login.html')
        else:
            flash("bad")
            return redirect('/')

@app.route('/logout', methods=['POST'])
def logout():
    session['current_id'] = None
    return redirect('/')



if __name__ == "__main__":
    app.run(debug=True)