
import os
import secrets
import requests
from flask import Flask, request, redirect, session, jsonify

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")
CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY")
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("TIKTOK_REDIRECT_URI")

AUTH_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"


@app.get("/")
def home():
    return jsonify({
        "service": "Avtomobilini tani TikTok OAuth",
        "status": "running"
    })


@app.get("/login")
def login():
    if not all([app.secret_key, CLIENT_KEY, REDIRECT_URI]):
        return jsonify({
            "error": "Server environment variables are not configured"
        }), 500

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": "user.info.basic,video.list",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    from urllib.parse import urlencode
    return redirect(AUTH_URL + "?" + urlencode(params))


@app.get("/auth/callback")
def auth_callback():
    error = request.args.get("error")
    if error:
        return jsonify({
            "error": error,
            "description": request.args.get("error_description", "")
        }), 400

    code = request.args.get("code")
    state = request.args.get("state")

    expected_state = session.pop("oauth_state", None)
    if not expected_state or not secrets.compare_digest(
        expected_state, state or ""
    ):
        return jsonify({"error": "Invalid OAuth state"}), 400

    if not all([CLIENT_KEY, CLIENT_SECRET, REDIRECT_URI]):
        return jsonify({"error": "Server environment variables are not configured"}), 500

    if not code:
        return jsonify({"error": "TikTok did not return an authorization code"}), 400

    try:
        response = requests.post(
            TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
        )

        data = response.json()
        if response.status_code != 200 or data.get("error"):
            app.logger.warning("TikTok token exchange failed: HTTP %s", response.status_code)
            return jsonify({
                "error": "TikTok token exchange failed",
                "details": data.get("error_description")
            }), 502

        # Do not expose or log access tokens in the browser.
        # Secure token storage and Telegram integration will be added next.
        return (
            "<h2>TikTok authorization response received</h2>"
            "<p>Token exchange completed. Do not close your account's "
            "security settings until you confirm the app permissions.</p>"
            "<p>Next: configure secure token storage and profile/video retrieval.</p>"
        )

    except requests.RequestException:
        app.logger.exception("TikTok token endpoint request failed")
        return jsonify({"error": "Could not reach TikTok token endpoint"}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
  
