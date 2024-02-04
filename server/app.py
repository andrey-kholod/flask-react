from flask import Flask, request
from flask_bcrypt import Bcrypt
from config import ApplicationConfig
from models import db, User
from flask.json import jsonify

app = Flask(__name__)
app.config.from_object(ApplicationConfig)

bcrypt = Bcrypt(app)

db.init_app(app)

with app.app_context():
    db.create_all()
    
@app.route('/register', methods=['POST'])
def register_user():
    email = request.json['email']
    password = request.json['password']
    
    user_exists = User.query.filter_by(email=email).first() is not None
    
    if user_exists:
        return jsonify({"error": "User already exists"}), 409
    
    hashed_pass = bcrypt.generate_password_hash(password)
    new_user = User(email=email, password=hashed_pass)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        "id": new_user.id,
        "email": new_user.email
    })
    
@app.route('/login', methods=['POST'])
def login_user():
    email = request.json['email']
    password = request.json['password']
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"error": "Unathorized"}), 401
    
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unathorized, wrong password"}), 401
    
    return jsonify({
        "id": user.id,
        "email": user.email
    })
    

if __name__ == '__main__':
   app.run(debug=True) 