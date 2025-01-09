from flask import Flask, request, jsonify
import hmac
import hashlib
import requests

app = Flask(__name__)

# Secret pour valider les requêtes
GITHUB_SECRET = "imtSecretHook123"

def validate_signature(payload, signature):
    """Vérifie que le webhook provient bien de GitHub."""
    mac = hmac.new(GITHUB_SECRET.encode(), msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(f"sha256={mac.hexdigest()}", signature)

@app.route('/webhook', methods=['POST'])
def webhook():
    # Lire la requête
    signature = request.headers.get('X-Hub-Signature-256')
    payload = request.get_data()

    # Valider la signature (si un secret est défini)
    if GITHUB_SECRET and not validate_signature(payload, signature):
        return jsonify({"error": "Invalid signature"}), 403

    # Lire les données JSON
    event = request.json
    if event['ref'] == 'refs/heads/main':  # Vérifie que le push est sur la branche `main`
        print(f"Push détecté : {event['head_commit']['message']}")
        trigger_pipeline(event)
    return jsonify({"status": "success"}), 200

def trigger_pipeline(event):
    """Déclenche le pipeline via une requête POST vers /deploy."""
    print("Déclenchement du pipeline...")
    try:
        deploy_payload = {
            "repo_url": event['repository']['clone_url']
        }
        headers = {
            "Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIwMTM4NjE2IiwiZW1haWwiOm51bGwsInJvbGUiOiJ2aWV3ZXIiLCJleHAiOjE3MzY0OTY2NzR9.60Z1TVaN2IuZB1Hd5qyM0BDdSBPgXhm_jEfJ1x1g4H0"  # token
        }
        # Envoi de la requête POST à /deploy
        response = requests.post("http://127.0.0.1:5000/deploy", json=deploy_payload, headers=headers)

        if response.status_code == 200:
            print(f"Pipeline déclenché avec succès pour le commit : {event['head_commit']['id']}")
        else:
            print(f"Erreur lors du déclenchement du pipeline : {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Erreur lors de l'appel au pipeline : {e}")

if __name__ == '__main__':
    app.run(port=5001, debug=True)

