# Flask-RestAPI-JWT-Swagger
Flask REST API backend for admin login with JWT and Swagger UI

Setup
=====

- Create and activate a vitualenv
- Run `pip install -r requirements.txt`
- Start server using `python server.py`

**Website**

- Access site at /. Not much there, just a basic example for logging in

**Admin**

- Access admin at /admin

**API auth**

- POST /api/v1/auth {'username': '', 'password': ''}
- Returns JSON with {'access_token':''}  
- Then request from API using header 'Authorization: JWT $token'

**Tests**

- Run tests using `python test.py`

## Swagger UI
Hosted Locally
http://127.0.0.1:5000/swagger/
