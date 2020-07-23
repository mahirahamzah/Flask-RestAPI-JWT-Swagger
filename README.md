# Flask-RestAPI-JWT-Swagger
Flask REST API backend for admin login with JWT and Swagger UI

Setup
=====

- Create and activate a vitualenv
- Run `pip install -r requirements.txt`
- Start api using `python server.py`

**Functionality**

1. Non-authenticate user (no login required) can read-only all driver and vehicles
2. Admin (login required) can create, delete and update users, driver, vehicles
3. Password is stored in hashed

# SQLite Database
I'm using SQLite for database creating a table name driverdb
Installing SQLite guide : https://www.sqlitetutorial.net/download-install-sqlite/

## How to seup database
Create the initial database by import the db object from an interactive Python shell and run the SQLAlchemy.create_all() method to create the tables and database
`from api.py import db`
`db.create_all()`


## Swagger UI
Hosted Locally
http://127.0.0.1:5000/swagger/

### Troubleshoot
If error 'No API definition provided': Force refresh http://127.0.0.1:5000/static/swagger.json
