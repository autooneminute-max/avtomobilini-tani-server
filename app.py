
import os
import secrets
import requests
from flask import Flask, request, redirect, session, jsonify
import html


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

    if not all([app.secret_key, CLIENT_KEY, CLIENT_SECRET, REDIRECT_URI]):
        return jsonify({
            "error": "Server environment variables are not configured"
        }), 500

    if not code:
        return jsonify({
            "error": "TikTok did not return an authorization code"
        }), 400

    try:
        token_response = requests.post(
            TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            timeout=20,
        )

        token_data = token_response.json()

        if token_response.status_code != 200 or token_data.get("error"):
            app.logger.warning(
                "TikTok token exchange failed: HTTP %s",
                token_response.status_code
            )
            return jsonify({
                "error": "TikTok token exchange failed",
                "details": token_data.get("error_description", "")
            }), 502

        access_token = token_data.get("access_token")
        if not access_token:
            return jsonify({
                "error": "TikTok response did not contain an access token"
            }), 502

        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        # Fetch basic profile information.
        profile_response = requests.get(
            "https://open.tiktokapis.com/v2/user/info/",
            params={
                "fields": "open_id,display_name,avatar_url"
            },
            headers=headers,
            timeout=20,
        )

        if profile_response.status_code != 200:
            app.logger.warning(
                "TikTok profile request failed: HTTP %s",
                profile_response.status_code
            )
            return jsonify({
                "error": "Could not retrieve TikTok profile",
                "status": profile_response.status_code
            }), 502

        profile_data = profile_response.json()
        profile = profile_data.get("data", {}).get("user", {})

        if not profile:
            return jsonify({
                "error": "TikTok profile response did not contain user data"
            }), 502

        # Fetch recent public videos.
        videos_response = requests.post(
            "https://open.tiktokapis.com/v2/video/list/",
            params={
                "fields": (
                    "id,title,video_description,create_time,"
                    "cover_image_url,share_url"
                )
            },
            headers={
                **headers,
                "Content-Type": "application/json",
            },
            json={"max_count": 10},
            timeout=20,
        )

        if videos_response.status_code != 200:
            app.logger.warning(
                "TikTok video list request failed: HTTP %s",
                videos_response.status_code
            )
            return jsonify({
                "error": "Could not retrieve TikTok videos",
                "status": videos_response.status_code
            }), 502

        videos_data = videos_response.json()
        videos = videos_data.get("data", {}).get("videos", [])

        # Show only selected profile/video fields. Never return tokens.
        display_name = html.escape(
            str(profile.get("display_name") or "Not provided")
        )

        page = [
            "<!doctype html><html><head>",
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>TikTok connection</title></head><body>",
            "<h2>TikTok authorization successful</h2>",
            f"<h3>Profile: {display_name}</h3>",
            f"<p>Public videos retrieved: {len(videos)}</p>",
            "<h3>Recent videos</h3><ul>",
        ]

        for video in videos:
            title = html.escape(
                str(video.get("title") or video.get("video_description") or "Untitled video")
            )
            share_url = str(video.get("share_url") or "")
            page.append(f"<li>{title}")

            if share_url.startswith("https://www.tiktok.com/"):
                safe_url = html.escape(share_url, quote=True)
                page.append(f' — <a href="{safe_url}">Open video</a>')

            page.append("</li>")

        page.extend([
            "</ul>",
            "<p>The access token was not displayed.</p>",
            "</body></html>",
        ])

        return "".join(page)

    except requests.RequestException:
        app.logger.exception("TikTok API request failed")
        return jsonify({
            "error": "Could not reach a TikTok API endpoint"
        }), 502
    except ValueError:
        app.logger.warning("TikTok returned an invalid JSON response")
        return jsonify({
            "error": "TikTok returned an invalid response"
        }), 502
        


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
  
