# Backend (app.py)
from flask import Flask, request, jsonify, redirect, render_template, make_response, session
from flask_cors import CORS
from git import Repo
from oauth2client import client
import paramiko
import docker
import os
import git
import json
from functools import wraps

from jwt import encode, decode

from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
CORS(app)

# Configuration
CONFIG = {
    'GITHUB_CLIENT_ID': os.getenv('GITHUB_CLIENT_ID'),
    'GITHUB_CLIENT_SECRET': os.getenv('GITHUB_CLIENT_SECRET'),
    'GITHUB_CALLBACK_URL': os.getenv('GITHUB_CALLBACK_URL', 'http://localhost:5000/auth/callback'),
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'your-secret-key'),
    'VM_HOST': os.getenv('VM_HOST'),
    'VM_USER': os.getenv('VM_USER'),
    'VM_KEY_PATH': os.getenv('VM_KEY_PATH'),
}

# Database simulation (in production, use a real database)
users_db = {}

# User roles and permissions
ROLES = {
    'admin': ['deploy', 'view_logs', 'manage_users'],
    'developer': ['deploy', 'view_logs'],
    'viewer': ['view_logs']
}

app.secret_key = 'IMTCICD-SecretKey'


# Decorator for role-based access control
def require_role(required_role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth_token = request.headers.get('Authorization')
            if not auth_token:
                return jsonify({'error': 'No authorization token'}), 401

            # Verify token and get user role
            user_role = verify_token(auth_token)  # Implement this function
            if not user_role or user_role not in ROLES:
                return jsonify({'error': 'Invalid token'}), 401

            if required_role not in ROLES[user_role]:
                return jsonify({'error': 'Insufficient permissions'}), 403

            return f(*args, **kwargs)

        return wrapped

    return decorator


# Auth utils
import jwt
from datetime import datetime, timedelta
import requests


def create_jwt_token(user_data):
    """Create a JWT token for the user"""
    payload = {
        'user_id': user_data['id'],
        'email': user_data['email'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, CONFIG['JWT_SECRET_KEY'], algorithm='HS256')


def verify_token(token):
    """Verify JWT token and return user role"""
    try:
        payload = jwt.decode(token.split(' ')[1], CONFIG['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload.get('role')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_github_user_data(access_token):
    """Get user data from GitHub API"""
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get('https://api.github.com/user', headers=headers)
    if response.status_code == 200:
        return response.json()
    return None


def get_or_create_user(github_data):
    """Get existing user or create new one"""
    user_id = str(github_data['id'])
    if user_id not in users_db:
        users_db[user_id] = {
            'id': user_id,
            'email': github_data['email'],
            'username': github_data['login'],
            'role': 'viewer'  # Default role for new users
        }
    return users_db[user_id]


# Routes
@app.route('/auth/github', methods=['GET'])
def github_login():
    """Start GitHub OAuth flow"""
    return redirect(f'https://github.com/login/oauth/authorize?'
                    f'client_id={CONFIG["GITHUB_CLIENT_ID"]}&'
                    f'redirect_uri={CONFIG["GITHUB_CALLBACK_URL"]}&'
                    f'scope=user:email')


@app.route('/auth/getToken', methods=['GET'])
def github_callback():
    """Handle GitHub OAuth callback"""
    code = request.args.get('code')
    if not code:
        return redirect("/")

    # Exchange code for access token
    response = requests.post(
        'https://github.com/login/oauth/access_token',
        headers={'Accept': 'application/json'},
        data={
            'client_id': CONFIG['GITHUB_CLIENT_ID'],
            'client_secret': CONFIG['GITHUB_CLIENT_SECRET'],
            'code': code,
            'redirect_uri': CONFIG['GITHUB_CALLBACK_URL']
        }
    )

    if response.status_code != 200:
        return jsonify({'error': 'Failed to get access token'}), 400

    access_token = response.json().get('access_token')
    if not access_token:
        return jsonify({'error': 'No access token received'}), 400

    # Get user data from GitHub
    github_user = get_github_user_data(access_token)
    if not github_user:
        return jsonify({'error': 'Failed to get user data'}), 400

    # Get or create user in our system
    user = get_or_create_user(github_user)

    # Create JWT token
    token = create_jwt_token(user)
    return token, 200

@app.route('/auth/callback', methods=['GET'])
def handle_github_callback():
    return render_template('callback.html')

@app.route('/index.html', methods=['GET'])
def get_index():
    return render_template('index.html')


@app.route('/auth/verify', methods=['GET'])
def verify_auth():
    """Verify authentication token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'No authorization header'}), 401

    user_role = verify_token(auth_header)
    if not user_role:
        return jsonify({'error': 'Invalid token'}), 401

    return jsonify({'role': user_role, 'permissions': ROLES[user_role]})


@app.route('/deploy', methods=['POST'])
@require_role('viewer')
def deploy():
    """Handle deployment request"""
    try:
        # 1. Pull latest code from GitHub
        repo_url = request.json.get('repo_url')
        clone_github_repo(repo_url, '/tmp/app')
        print("Cloned repo successfully")

        # 2. Build Docker image
        client = docker.from_env()
        image = client.images.build(path='/tmp/app', tag='app:latest')

        # 3. Connect to VM and deploy
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(CONFIG['VM_HOST'], username=CONFIG['VM_USER'], key_filename=CONFIG['VM_KEY_PATH'])

        # 4. Run deployment commands
        commands = [
            'docker pull app:latest',
            'docker stop app || true',
            'docker rm app || true',
            'docker run -d --name app app:latest'
        ]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            if stderr.channel.recv_exit_status() != 0:
                raise Exception(f"Deployment failed: {stderr.read().decode()}")

        return jsonify({'status': 'success', 'message': 'Deployment completed'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/pipeline/status', methods=['GET'])
@require_role('view_logs')
def pipeline_status():
    """Get current pipeline status"""
    # Implement pipeline status tracking
    pass

@app.route('/', methods=['GET'])
def get_authpage():
    return render_template('GitAuth.html')

# In-memory storage for pipelines (replace with database in production)
pipelines_db = {}

@app.route('/api/pipelines', methods=['GET'])
@require_role('view_logs')
def get_pipelines():
    """Get all pipelines"""
    pipelines_list = list(pipelines_db.values())
    # Sort by creation date, newest first
    pipelines_list.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify(pipelines_list)


@app.route('/api/pipelines', methods=['POST'])
@require_role('deploy')
def create_pipeline():
    """Create a new pipeline"""
    data = request.json
    if not all(key in data for key in ['name', 'status', 'repo_url']):
        return jsonify({'error': 'Missing required fields'}), 400

    pipeline_id = str(len(pipelines_db) + 1)

    pipeline = {
        'id': pipeline_id,
        'name': data['name'],
        'status': data['status'],
        'repo_url': data['repo_url'],
        'created_at': datetime.utcnow().isoformat(),
        'created_by': get_user_from_token(request.headers['Authorization'])
    }

    pipelines_db[pipeline_id] = pipeline
    return jsonify(pipeline), 201


@app.route('/api/pipelines/<pipeline_id>/cancel', methods=['POST'])
@require_role('deploy')
def cancel_pipeline(pipeline_id):
    """Cancel a running pipeline"""
    if pipeline_id not in pipelines_db:
        return jsonify({'error': 'Pipeline not found'}), 404

    pipeline = pipelines_db[pipeline_id]
    if pipeline['status'] != 'running':
        return jsonify({'error': 'Pipeline is not running'}), 400

    pipeline['status'] = 'cancelled'
    return jsonify(pipeline)


def get_user_from_token(auth_header):
    """Extract user information from JWT token"""
    try:
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, CONFIG['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload.get('email')
    except:
        return None

def clone_github_repo(repo_url, destination_folder):
    try:
        print(f"Clonage du dépôt depuis {repo_url} dans {destination_folder}...")
        Repo.clone_from(repo_url, destination_folder)
        print("Clonage terminé avec succès !")
    except Exception as e:
        print(f"Erreur lors du clonage : {e}")

if __name__ == '__main__':
    app.run(debug=True)


