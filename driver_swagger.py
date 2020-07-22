from flask import Flask, request, jsonify, make_response,session,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from markupsafe import escape
from flask_swagger_ui import get_swaggerui_blueprint

app = Flask (__name__)

### swagger specific ###
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "FlaskWebApp"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

### end swagger specific ###


app.config['SECRET_KEY'] = 'UNWz5SallYG9TSsdZOmM7CyNOweeEUjE'
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///driverdb.db'

db=SQLAlchemy(app)

#MODEL

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))

class Driver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    active = db.Column(db.Boolean)
    vehicles = db.relationship('Vehicle', backref='drive')

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20))
    platenum = db.Column(db.String(20))
    capacity=db.Column(db.Integer)
    driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return make_response('Not Admin : Permission Denied', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}),401

        return f(current_user, *args, **kwargs)

    return decorated


#CONTROLLER USER

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

   # if not current_user.admin:
    #    return jsonify({'message' : 'Cannot perform that function!'})

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
def create_user(current_user):
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

#CONTROLLER DRIVER

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

    new_driver = Driver(name=data['name'], active=True)
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


#CONTROLLER VEHICLE

@app.route('/vehicle', methods=['GET'])
def get_all_vehicles():

    vehicles = Vehicle.query.all()

    output = []

    for vehicle in vehicles:
        vehicle_data = {}
        vehicle_data['id'] = vehicle.id
        vehicle_data['type'] = vehicle.type
        vehicle_data['platenum'] = vehicle.platenum
        vehicle_data['capacity'] = vehicle.capacity
        vehicle_data['driver_id'] = vehicle.driver_id
        output.append(vehicle_data)


    return jsonify({'vehicles' : output})

@app.route('/vehicle/<vehicle_id>', methods=['GET'])
def get_one_vehicle(vehicle_id):
    vehicle = Vehicle.query.filter_by(id=vehicle_id).first()

    if not vehicle:
        return jsonify({'message':'No vehicle found'})

    vehicle_data = {}
    vehicle_data['id'] = vehicle.id
    vehicle_data['type'] = vehicle.type
    vehicle_data['platenum'] = vehicle.platenum
    vehicle_data['capacity'] = vehicle.capacity
    vehicle_data['driver_id'] = vehicle.driver_id

    return(vehicle_data)

@app.route('/vehicle', methods=['POST'])
@token_required
def create_vehicle(current_user):
    data = request.get_json()

    new_vehicle = Vehicle(type=data['type'], platenum=data['platenum'],capacity=data['capacity'],driver_id=data['driver_id'])
    db.session.add(new_vehicle)
    db.session.commit()

    return jsonify({'message':'Vehicle created'})

@app.route('/vehicle/<vehicle_id>',methods=['PUT'])
@token_required
def update_driver(current_user, vehicle_id):
    vehicle = Vehicle.query.filter_by(id=vehicle_id).first()

    if not vehicle:
        return jsonify({'message':'No vehicle found'})

    vehicle.type = data['type']
    vehicle.platenum = data['platenum']
    vehicle.capacity = data['capacity']
    vehicle.drive_is = data['driver_id']
    db.session.commit()

    return jsonify({'message': 'Vehicle data has been updates'})

@app.route('/vehicle/<vehicle_id>', methods = ['DELETE'])
@token_required
def delete_vehicle(current_user, vehicler_id):
    vehicle = Vehicle.query.filter_by(id=vehicle).first()

    if not vehicle:
        return jsonify({'message':'No vehicle found'})

    db.session.delete(vehicle)
    db.session.commit()

    return jsonify({'message': 'Vehicle has been deleted'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Not Admin : Permission Denied', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Not Admin : Permission Denied', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' :datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401,{'WWW-Authenticate': 'Basic realm="Login required!"'})

if __name__ =='__main__':
    app.run(debug=True)