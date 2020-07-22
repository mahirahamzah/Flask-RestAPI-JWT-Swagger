# Flask-RestAPI-JWT-Swagger
Flask REST API backend for admin login with JWT and Swagger UI

Setup
=====

- Create and activate a vitualenv
- Run `pip install -r requirements.txt`
- Start server using `python server.py`

**Functionality**

1. Non-authenticate user (no login required) can view all
2. Admin (login required) can create, delete and update
3. Password is stored in hashed

**Admin**

- Access admin at /login

**API auth**

- POST /api/v1/auth {'username': '', 'password': ''}
- Returns JSON with {'access_token':''}  
- Then request from API using header 'Authorization: JWT $token'

**Tests**

- Run tests using `python test.py`

## Swagger UI
Hosted Locally
http://127.0.0.1:5000/swagger/
