import http.server
import socketserver
import threading
import time
from http.server import ThreadingHTTPServer
import tarfile

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
import subprocess


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
    'VM_PASS': os.getenv('VM_PASS'),
}

# Database simulation (in production, use a real database)
users_db = {}

# User roles and permissions
ROLES = {
    'admin': ['deploy', 'view_logs', 'manage_users'],
    'developer': ['deploy', 'view_logs'],
    'viewer': ['deploy','view_logs']
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

            if required_role != user_role:
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
        if os.path.isdir("./tmp.old") and os.path.isdir("./tmp"): #If tmp.old already exists, we can delete it as it will be replaced by next tmp:
            os.system("powershell /c \"Remove-Item -Recurse -Force tmp.old\"")
            print("Deleted tmp.old")

        if os.path.isdir("./tmp"): #If tmp folder already exists, we rename it to "tmp.old"
            os.rename("tmp", "tmp.old")
            print("Renamed tmp to tmp.old")
            os.system("powershell /c \"Remove-Item ./tmp/librarimt.tar.gz\"")
            print("Deleted project tar.gz")

        # 1. Pull latest code from GitHub
        repo_url = request.json.get('repo_url')
        clone_github_repo(repo_url, './tmp/app')
        print("Cloned repo successfully")

        # Create project archive
        with tarfile.open("./tmp/librarimt.tar.gz", "w:gz") as archive:
            archive.add("./tmp/app/.", arcname=os.path.basename("./tmp/app/."))

        # 2. Compilation maven/gradle avec run des TU
        """# Run tests with Maven or Gradle"""
        BACKEND_PATH = r"./tmp/app/LibrarIMTBackend"
        compile_and_test_java_project(BACKEND_PATH)
        print("Compilation maven TU successfully")

        # 3. Connect to VM and deploy
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(CONFIG['VM_HOST'], username=CONFIG['VM_USER'], password=CONFIG['VM_PASS'])

        # 4. Gathering Local IPV4
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        LHOST_IP = s.getsockname()[0]

        # 5. Open Python HTTP Server so the code is available to the VM
        http_server_port = 8001
        handler = http.server.SimpleHTTPRequestHandler
        server = ThreadingHTTPServer(("0.0.0.0", http_server_port), handler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print("HTTP Server listening on 0.0.0.0:", http_server_port)

        # 6. Copy app to VM
        channel = ssh.invoke_shell() #We first open a terminal then send keyboard inputs to it
        channel.send("mkdir LibrarIMT\n")
        print("Creating LibrarIMT folder")
        time.sleep(1)
        run_ssh_sudo_command("cd LibrarIMT && sudo docker-compose down --rmi all --volumes --remove-orphans",ssh) #Using sudo will request the password
        print("Exiting former containers, deleting docker images on VM")
        time.sleep(2) #Just to be sure
        print("2sec timer over")
        channel.send("rm -rf LibrarIMT\n")
        channel.send("rm -rf librarimt.tar.*\n")
        time.sleep(2)
        print("Downloading project from CICD server...")
        print("$ wget "+str(LHOST_IP)+":"+str(http_server_port)+"/tmp/librarimt.tar.gz\n")
        stdin, stdout, stderr = ssh.exec_command("wget "+str(LHOST_IP)+":"+str(http_server_port)+"/tmp/librarimt.tar.gz\n") #Downloading project from LHOST
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0 or exit_status == 8:
            print("Project downloaded succesfully on: "+ CONFIG['VM_HOST'])
        else:
            print("Something may have gone wrong while downloading files. Code: "+str(exit_status)+". Skipping")

        # Extracting the archive
        channel.send("mkdir LibrarIMT\n")
        channel.send("tar -xf librarimt.tar.gz -C LibrarIMT\n")
        time.sleep(2)

        # 7. Executing Docker-Compose
        print("Executing Docker-compose")
        exit_status = run_ssh_sudo_command("cd LibrarIMT && sudo docker-compose up -d --build",ssh)
        if exit_status == 0:
            print("Docker-compose finished succesfully on: "+ CONFIG['VM_HOST'])
        else:
            return jsonify({'status': 'error', 'message': "Issue encountered with running docker-compose up -d on "+CONFIG['VM_HOST']+" Code: "+str(exit_status)}), 500

        return jsonify({'status': 'success', 'message': 'Deployment completed'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


def run_ssh_sudo_command(command,ssh):
    session = ssh.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty()
    session.exec_command("sudo bash -c \""+ command +"\"")
    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)
    stdin.write(CONFIG['VM_PASS'] + '\n')
    stdin.flush()
    exit_status = stdout.channel.recv_exit_status()
    return exit_status


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
        print(f"Cloning {repo_url} into {destination_folder}...")
        Repo.clone_from(repo_url, destination_folder)
    except Exception as e:
        return jsonify({"status" : "error", "message": e}), 500


def run_maven_command(command, project_path):
    try:
        maven_executable = "mvn"
        full_command = [maven_executable] + command
        print (full_command)
        print(f"Exécution de la commande : {' '.join(full_command)} dans {project_path}")
        result = subprocess.run(full_command, cwd=project_path, check=True, text=True, capture_output=True)
        print("Sortie standard :")
        print(result.stdout)
    except FileNotFoundError:
        return jsonify({"status" : "error", "message": "Maven was not found on CICD Server: "+ str(FileNotFoundError)}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({"status" : "error", "message": str(e)}), 500

def compile_and_test_java_project(project_path):
    # Liste des commandes à exécuter
    commands = [
    ["clean", "compile"],  # Compilation
    ["test"]  # Tests unitaires
    ]
    for command in commands:
        run_maven_command(command, project_path)

# Chemin en dur pour le répertoire du fichier Docker Compose
DOCKER_COMPOSE_PATH = r"./tmp/app"

def run_command(command, working_dir=None):
    """
    Exécute une commande système dans un répertoire spécifique.
    :param command: Liste des arguments de la commande.
    :param working_dir: Répertoire dans lequel exécuter la commande.
    """
    try:
        print(f"Exécution de la commande : {command} dans {working_dir or os.getcwd()}")
        result = subprocess.run(command, cwd=working_dir, check=True, text=True, capture_output=True)
        print("Sortie standard")
        print(result.stdout)
    except FileNotFoundError:
        print("Erreur : Commande introuvable.")
        exit(1)
    except subprocess.CalledProcessError as e:
        print("Erreur lors de l'exécution de la commande.")
        print("Sortie standard")
        print(e.stdout)
        print("Sortie d'erreur")
        print(e.stderr)
        exit(1)

def run_docker_compose(compose_path):
    """
    Exécute Docker Compose à partir d'un chemin spécifique.
    :param compose_path: Chemin contenant le fichier docker-compose.yml.
    """
    docker_compose_file = os.path.join(compose_path, "compose.yml")
    if not os.path.exists(docker_compose_file):
        print(f"Erreur : Aucun fichier docker-compose.yml trouvé dans {compose_path}.")
        exit(1)

    command = ["docker-compose", "up", "--build", "-d"]
    run_command(command, compose_path)


if __name__ == '__main__':
    app.run(debug=True)


