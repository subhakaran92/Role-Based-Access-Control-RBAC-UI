from flask import Flask, request, jsonify,render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps 
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Initialize Flask app and dependencies
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Replace with a secure key

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Create the database
with app.app_context():
    db.create_all()
#Serve the HTML page

@app.route('/')

def home():

    return render_template('loginpage.html')



# User registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered successfully"), 201

# User login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200
    return jsonify(message="Invalid credentials"), 401

# Role-based access control decorator
def role_required(role):
    def wrapper(func):
        @wraps(func)  # Preserve the original function's name
        @jwt_required()
        def decorated(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user['role'] != role:
                return jsonify(message="Access denied"), 403
            return func(*args, **kwargs)
        return decorated
    return wrapper

# Protected route for admin
@app.route('/admin', methods=['GET'])
@role_required('admin')
def admin_route():
    return jsonify(message="Welcome, Admin!")

# Protected route for users
@app.route('/user', methods=['GET'])
@role_required('user')
def user_route():
    return jsonify(message="Welcome, User!")

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
