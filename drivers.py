from flask import Flask, request, jsonify, make_response,session,redirect,url_for
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from markupsafe import escape
import models
from models import *

app = Flask (__name__)

app.config['SECRET_KEY'] = 'UNWz5SallYG9TSsdZOmM7CyNOweeEUjE'
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///driverdb.db'

#=SQLAlchemy(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}),401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):


    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        output.append(user_data)


    return jsonify({'users' : output})

@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password

    return jsonify({'user' : user_data})

@app.route('/user',methods=['POST'])
@token_required
def create_user():

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user=User(public_id=str(uuid.uuid4()), name=data['name'],password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'User have been deleted'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        session['username'] = user.name
        token = jwt.encode({'public_id' : user.public_id, 'exp' :datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/driver', methods=['GET'])
def get_all_drivers():

    drivers = Driver.query.all()

    output = []

    for driver in drivers:
        driver_data = {}
        driver_data['id'] = driver.id
        driver_data['name'] = driver.name
        driver_data['active'] = driver.active
        output.append(driver_data)


    return jsonify({'drivers' : output})

@app.route('/driver/<driver_id>', methods=['GET'])
@token_required
def get_one_driver(driver_id):
    driver = Driver.query.filter_by(id=driver_id).first()

    if not driver:
        return jsonify({'message':'No driver found'})

    driver_data = {}
    driver_data['id'] = driver.id
    driver_data['name'] = driver.name
    driver_data['complete'] = driver.complete

    return(driver_data)

@app.route('/driver', methods=['POST'])
@token_required
def create_driver(current_user):
    data = request.get_json()

    new_driver = Driver(name=data['name'], complete=False)
    db.session.add(new_driver)
    db.session.commit()

    return jsonify({'message':'Driver created'})

@app.route('/driver/<driver_id>',methods=['PUT'])
@token_required
def complete_driver(current_user, driver_id):
    driver = Driver.query.filter_by(id=driver_id).first()

    if not driver:
        return jsonify({'message':'No driver found'})

    driver.complete = True
    db.session.commit()

    return jsonify({'message': 'Driver has been completed'})

@app.route('/driver/<driver_id>', methods = ['DELETE'])
@token_required
def delete_driver(current_user, driver_id):
    driver = Driver.query.filter_by(id=driver_id).first()

    if not driver:
        return jsonify({'message':'No driver found'})

    db.session.delete(driver)
    db.session.commit()

    return jsonify({'message': 'Driver has been deleted'})


#app.route('/vehicle',)

if __name__ =='__main__':
    app.run(debug=True)
