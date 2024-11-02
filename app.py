from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

users_db = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/get-jwt', methods=['GET'])
def get_jwt():
    return jsonify({'message': 'Use /login to obtain a JWT.'})


@app.route('/set-jwt', methods=['POST'])
def set_jwt():
    return jsonify({'message': 'Tokens are generally issued and not set manually.'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users_db.get(username)

    if user and user['password'] == password:
        token = jwt.encode(dict(username=username, exp=datetime.datetime.utcnow() + datetime.timedelta(hours=1)), app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token})

    return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users_db:
        return jsonify({'message': 'User already exists'}), 400

    users_db[username] = {'password': password}
    return jsonify({'message': 'User registered successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True)