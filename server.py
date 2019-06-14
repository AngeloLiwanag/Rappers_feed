from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re 
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = "Secret"
bcrypt = Bcrypt(app)

#global key
USER_KEY = "user_id" 

#log_reg home route
@app.route('/') 
def login_register():
    mysql = connectToMySQL('private_wall')
    users = mysql.query_db('SELECT * FROM users;')
    print(users)
    return render_template('log_reg_page.html')

#this route gets the information passed from the register form
#also validates the users name, email, password with flash messages 
@app.route('/register', methods =['POST'])
def register():
    is_valid = True
    if len(request.form['fname']) < 2:
        is_valid = False
        flash('Please enter your first name')

    if len(request.form['lname']) < 2:
        is_valid = False
        flash('Please enter your last name')   

    if not EMAIL_REGEX.match(request.form['email']):
        flash ("Invalid email address!")
    
    if len(request.form['password']) < 8:
        is_valid = False
        flash('Please enter a password with more than 8 characters')   
    
    if not is_valid:   
        return redirect('/') 
    else:
        # this line hashes password and compares if the confirmed password
        # and matches it with the orginal passwrord
        hashed_password = bcrypt.generate_password_hash(request.form['password'])
        password_string = request.form['confirm_password']
        is_match = bcrypt.check_password_hash(hashed_password, password_string)

        # if the password is a match, add this new user into the data base
        if is_match:
            mysql = connectToMySQL('private_wall')
            query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(fn)s, %(ln)s, %(em)s, %(hp)s);"
            data = {
                'fn' : request.form['fname'],
                'ln' : request.form['lname'],
                'em' : request.form['email'],
                'pw' : request.form['password'],
                'hp' : hashed_password 
            }
            user_id = mysql.query_db(query, data)
            session[USER_KEY] = user_id #remember the person that is logged in
            return redirect('/main_page') #direct that person into the main_page route 

# this route logs the registered user into the main_page route with validations
@app.route('/login', methods=['POST']) 
def login():
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False

    if len(request.form['password']) < 8:
        is_valid = False
    
    if not is_valid:
        return redirect('/')

    # this double checks if the user is in the database
    mysql = connectToMySQL('private_wall')
    query = 'SELECT id, password FROM users WHERE email = %(em)s'
    data = { 'em' : request.form['email']}
    user_id= mysql.query_db(query, data)
    
    # checks if the user's password matches to log in, if so log in to the main_page route
    # else return them back into the login registration page
    if bcrypt.check_password_hash(user_id[0]['password'], request.form['password']):
        session[USER_KEY] = user_id[0]['id']
        return redirect('/main_page')
    else:
        return redirect('/')

# this is the main_page route and where most of the redirecting will happen
@app.route('/main_page')
def main_page():
    if not USER_KEY in session:
        return redirect('/')
    
    #this shows the users equal to whos logged in
    mysql = connectToMySQL('private_wall')
    query = "SELECT * FROM users WHERE id = %(id)s"
    data = {'id': session[USER_KEY]}
    user_id = mysql.query_db(query, data)[0]
    session['first_name']=user_id['first_name']

    #this grabs the first name and id from the users table where the id isnt equal to the users id whos logged in
    mysql = connectToMySQL('private_wall')
    query = "SELECT first_name, id FROM users WHERE id !=%(id)s"
    users = mysql.query_db(query, data)
    print('*' *80, users)

    # this gets everything from post and joins it to the table users and chooses the sender_id from the posts table which is equal to 
    # the id from the users table where the recipients_id is the dame of the logged in user's id and order them by the posts created at descending order
    query = "SELECT * FROM posts JOIN users ON posts.sender_id = users.id WHERE recipient_id = %(logged)s ORDER BY posts.created_at DESC"
    data = {
        'logged' : session[USER_KEY]
    }
    posts = connectToMySQL('private_wall').query_db(query,data)
    print(posts)

    return render_template('main_wall.html', users = users, posts = posts)

# simple logout page which clears the user in session
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

#this route creates a new post
@app.route('/create/<id>', methods=["POST"])
def create(id):
    if not USER_KEY in session:
        return redirect('/')
    
    #this line inserts a new post into the post table and creates new content from the sender id and recipient id
    insert = "INSERT INTO posts (content, sender_id, recipient_id) VALUES (%(content)s, %(id)s, %(rec)s);"
    data = {
        'content': request.form['content'],
        'id' : session[USER_KEY],
        'rec' : id
    }
    connectToMySQL('private_wall').query_db(insert, data)
    print(data)
    return redirect('/main_page')

#this route recieves post from other users
@app.route('/recieve')
def recieve():
    query = "SELECT * FROM posts JOIN users ON posts.sender_id = users.id ORDER BY posts.created_at DESC"
    posts = connectToMySQL('private_wall').query_db(query)
    print(posts)
    return render_template("main_wall.html", posts = posts)

# this route deletes the post from recipients
@app.route('/delete/<id>')
def delete(id):
    print("*"*60)
    print(id)
    query ="DELETE FROM posts WHERE id = %(id)s"
    data = {
        'id': id
    }
    connectToMySQL("private_wall").query_db(query, data)
    return redirect('/main_page')


if __name__ == "__main__":
    app.run(debug=True)

