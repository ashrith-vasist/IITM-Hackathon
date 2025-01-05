from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.security import check_password_hash
from flask_sqlalchemy import SQLAlchemy
import re
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
import base64
import os

app = Flask(__name__)


# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key_here"
app.config['SECRET_KEY'] = os.urandom(24)


db = SQLAlchemy(app)
jwt = JWTManager(app)

#User Database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(20), nullable=False)



@app.context_processor
def inject_user_status():
    user_logged_in = 'user_id' in session
    return dict(user_logged_in=user_logged_in)

#Just a test route
@app.route("/")
def index():
    return "Hello World"

#The Register Route
@app.route("/api/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        try:
            data = request.form
            #All the neccesary error codes are mentioned 
            required_fields = ("username", "email", "password", "full_name", "age", "gender")
            if not all(key in data for key in required_fields):
                return jsonify({
                    "status": "error",
                    "code": "INVALID_REQUEST",
                    "message": "Invalid request. Please provide all required fields: username, email, password, full_name, age, gender."
                }), 400

            if User.query.filter_by(username=data['username']).first():
                return jsonify({
                    "status": "error",
                    "code": "USERNAME_EXISTS",
                    "message": "The provided username is already taken. Please choose a different username."
                }), 409

            if User.query.filter_by(email=data['email']).first():
                return jsonify({
                    "status": "error",
                    "code": "EMAIL_EXISTS",
                    "message": "The provided email is already registered. Please use a different email address."
                }), 409

            if len(data['password']) < 8 or not re.search(r'[A-Z]', data['password']) or \
                    not re.search(r'[a-z]', data['password']) or not re.search(r'\d', data['password']) or \
                    not re.search(r'[!@#$%^&*(),.?":{}|<>]', data['password']):
                return jsonify({
                    "status": "error",
                    "code": "INVALID_PASSWORD",
                    "message": "Password must be at least 8 characters long and contain an uppercase letter, lowercase letter, number, and special character."
                }), 400

            if not data['age'] or int(data['age']) <= 0:
                return jsonify({
                    "status": "error",
                    "code": "INVALID_AGE",
                    "message": "Invalid age value. Age must be a positive integer."
                }), 400

            if not data['gender'].strip():
                return jsonify({
                    "status": "error",
                    "code": "GENDER_REQUIRED",
                    "message": "Gender field is required. Please specify the gender."
                }), 400

            #password is hased theough bcrypt and then encoded to base64
            hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
            hashed_password_str = base64.b64encode(hashed_password).decode('utf-8')

            new_user = User(
                username=data['username'],
                email=data['email'],
                password=hashed_password_str,
                full_name=data['full_name'],
                age=int(data['age']),
                gender=data['gender']
            )

            db.session.add(new_user)
            db.session.commit()

            message = {
                "status": "success",
                "message": "User successfully registered!",
                "data": {
                    "user_id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "full_name": new_user.full_name,
                    "age": new_user.age,
                    "gender": new_user.gender
                }
            }
            return render_template('register.html', message=message)
        except:
            message = {
                "status": "error",
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred. Please try again later."
            }
            return render_template('register.html', message=message)
        
    return render_template("register.html")
    
@app.route("/api/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            data = request.form.to_dict()

            # Check for missing fields
            if not all(key in data for key in ["username", "password"]):
                return jsonify({
                    "status": "error",
                    "code": "MISSING_FIELDS",
                    "message": "Missing fields. Please provide both username and password."
                }), 400

            # Validate user credentials
            user = User.query.filter_by(username=data['username']).first()
            if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), base64.b64decode(user.password)):
                return jsonify({
                    "status": "error",
                    "code": "INVALID_CREDENTIALS",
                    "message": "Invalid credentials. The provided username or password is incorrect."
                }), 401

            # Generate access token
            try:
                access_token = create_access_token(identity=str(user.id))
                app.logger.info(f"Generated Access Token: {access_token}")
            except Exception as e:
                app.logger.error(f"Error generating access token: {str(e)}")
                return jsonify({
                    "status": "error",
                    "code": "TOKEN_GENERATION_ERROR",
                    "message": "Error generating access token. Please try again."
                }), 500

            # Store user and token in session
            session['user_id'] = user.id
            session['username'] = user.username
            session['access_token'] = access_token

            # Return success response with token and redirect URL
            message = {
                "status": "success",
                "message": "Login successful",
                "data": {
                    "access_token": access_token,
                    "expires_in": 3600,
                    "user": {
                        "id": user.id,
                        "username": user.username
                    }
                }
            }
            return render_template("login.html", message=message)

        except Exception as e:
            app.logger.error(f"Error occurred during login: {str(e)}")
            return jsonify({
                "status": "error",
                "code": "INTERNAL_ERROR",
                "message": "Internal server error occurred. Please try again later."
            }), 500

    return render_template("login.html")