"""
OSINT Username Intelligence Tool - Backend
Ethical: Only queries publicly accessible URLs and official public APIs.
No authentication bypass, no private data access.
"""

import asyncio
import aiohttp
import json
import time
import re
import hashlib
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# ─────────────────────────────────────────────
# Platform definitions — public profile URLs only
# ─────────────────────────────────────────────
PLATFORMS = {
    # Dev / Code
    "GitHub": {
        "url": "https://github.com/{username}",
        "api": "https://api.github.com/users/{username}",
        "not_found": [404],
        "category": "Dev",
        "icon": "💻",
    },
    "GitLab": {
        "url": "https://gitlab.com/{username}",
        "api": None,
        "not_found": [404],
        "category": "Dev",
        "icon": "🦊",
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{username}",
        "api": None,
        "not_found": [404],
        "category": "Dev",
        "icon": "🪣",
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{username}",
        "api": None,
        "not_found": [404],
        "category": "Dev",
        "icon": "📦",
    },
    "PyPI": {
        "url": "https://pypi.org/user/{username}/",
        "api": None,
        "not_found": [404],
        "category": "Dev",
        "icon": "🐍",
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "api": "https://hacker-news.firebaseio.com/v0/user/{username}.json",
        "not_found": [404],
        "category": "Dev",
        "icon": "🟠",
    },
    "Dev.to": {
        "url": "https://dev.to/{username}",
        "api": "https://dev.to/api/users/by_username?url={username}",
        "not_found": [404],
        "category": "Dev",
        "icon": "👩‍💻",
    },
    # Social
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "api": "https://www.reddit.com/user/{username}/about.json",
        "not_found": [404],
        "category": "Social",
        "icon": "👽",
    },
    "Twitter/X": {
        "url": "https://twitter.com/{username}",
        "api": None,
        "not_found": [404],
        "category": "Social",
        "icon": "🐦",
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "api": None,
        "not_found": [404],
        "category": "Social",
        "icon": "📷",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "api": None,
        "not_found": [404],
        "category": "Social",
        "icon": "🎵",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "api": None,
        "not_found": [404],
        "category": "Social",
        "icon": "📌",
    },
    "Tumblr": {
        "url": "https://{username}.tumblr.com",
        "api": None,
        "not_found": [404],
        "category": "Social",
        "icon": "🔵",
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{username}",
        "api": None,
        "not_found": [404],
        "category": "Social",
        "icon": "🐘",
    },
    # Gaming
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "api": None,
        "not_found": [404],
        "category": "Gaming",
        "icon": "🎮",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "api": None,
        "not_found": [404],
        "category": "Gaming",
        "icon": "🟣",
    },
    "Roblox": {
        "url": "https://www.roblox.com/user.aspx?username={username}",
        "api": None,
        "not_found": [404],
        "category": "Gaming",
        "icon": "🧱",
    },
    # Creative / Content
    "Medium": {
        "url": "https://medium.com/@{username}",
        "api": None,
        "not_found": [404],
        "category": "Creative",
        "icon": "✍️",
    },
    "Behance": {
        "url": "https://www.behance.net/{username}",
        "api": None,
        "not_found": [404],
        "category": "Creative",
        "icon": "🎨",
    },
    "Dribbble": {
        "url": "https://dribbble.com/{username}",
        "api": None,
        "not_found": [404],
        "category": "Creative",
        "icon": "🏀",
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{username}",
        "api": None,
        "not_found": [404],
        "category": "Creative",
        "icon": "📸",
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{username}",
        "api": None,
        "not_found": [404],
        "category": "Creative",
        "icon": "🔊",
    },
    # Professional
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "api": None,
        "not_found": [404],
        "category": "Professional",
        "icon": "💼",
    },
    "AngelList": {
        "url": "https://angel.co/{username}",
        "api": None,
        "not_found": [404],
        "category": "Professional",
        "icon": "👼",
    },
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "api": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
        "not_found": [404],
        "category": "Security",
        "icon": "🔑",
    },
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; OSINT-Tool/1.0; +https://github.com/osint-tool)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


# ─────────────────────────────────────────────
# Async check — one platform
# ─────────────────────────────────────────────
async def check_platform(session, name, cfg, username, timeout=10):
    url = cfg["url"].replace("{username}", username)
    api_url = cfg.get("api") and cfg["api"].replace("{username}", username)
    result = {
        "platform": name,
        "url": url,
        "found": False,
        "category": cfg["category"],
        "icon": cfg["icon"],
        "data": {},
        "error": None,
        "response_time_ms": None,
    }
    try:
        t0 = time.monotonic()
        async with session.get(
            url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True, ssl=False
        ) as resp:
            elapsed = int((time.monotonic() - t0) * 1000)
            result["response_time_ms"] = elapsed
            status = resp.status
            if status not in cfg["not_found"] and status < 400:
                result["found"] = True
                # Try to get extra data from API if available
                if api_url:
                    result["data"] = await fetch_api_data(session, api_url, name)
            else:
                result["found"] = False
    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


async def fetch_api_data(session, api_url, platform_name):
    try:
        async with session.get(
            api_url, headers={**HEADERS, "Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(total=8), ssl=False
        ) as r:
            if r.status == 200:
                raw = await r.json(content_type=None)
                return parse_api_data(platform_name, raw)
    except Exception:
        pass
    return {}


def parse_api_data(platform, raw):
    """Extract useful fields from platform API responses."""
    if platform == "GitHub":
        return {
            "name": raw.get("name"),
            "bio": raw.get("bio"),
            "location": raw.get("location"),
            "company": raw.get("company"),
            "blog": raw.get("blog"),
            "public_repos": raw.get("public_repos"),
            "followers": raw.get("followers"),
            "following": raw.get("following"),
            "created_at": raw.get("created_at"),
            "avatar_url": raw.get("avatar_url"),
            "email": raw.get("email"),
            "twitter_username": raw.get("twitter_username"),
        }
    if platform == "Reddit":
        d = raw.get("data", {})
        return {
            "name": d.get("name"),
            "karma": d.get("total_karma"),
            "link_karma": d.get("link_karma"),
            "comment_karma": d.get("comment_karma"),
            "is_gold": d.get("is_gold"),
            "created_utc": d.get("created_utc"),
            "icon_img": d.get("icon_img"),
        }
    if platform == "HackerNews":
        if isinstance(raw, dict):
            return {
                "karma": raw.get("karma"),
                "about": raw.get("about"),
                "created": raw.get("created"),
            }
    if platform == "Dev.to":
        return {
            "name": raw.get("name"),
            "bio": raw.get("summary"),
            "location": raw.get("location"),
            "github_username": raw.get("github_username"),
            "twitter_username": raw.get("twitter_username"),
            "website_url": raw.get("website_url"),
            "joined_at": raw.get("joined_at"),
            "profile_image": raw.get("profile_image"),
        }
    if platform == "Keybase":
        users = raw.get("them", [])
        if users:
            u = users[0]
            profile = u.get("profile", {})
            return {
                "name": profile.get("full_name"),
                "bio": profile.get("bio"),
                "location": profile.get("location"),
                "proofs_summary": list(u.get("proofs_summary", {}).keys()),
            }
    return {}


# ─────────────────────────────────────────────
# Gravatar lookup (email only, ethical)
# ─────────────────────────────────────────────
async def check_gravatar(session, identifier):
    """Check Gravatar — works if identifier is an email."""
    try:
        h = hashlib.md5(identifier.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/{h}.json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                entry = data.get("entry", [{}])[0]
                return {
                    "found": True,
                    "display_name": entry.get("displayName"),
                    "about_me": entry.get("aboutMe"),
                    "location": entry.get("currentLocation"),
                    "urls": [u.get("value") for u in entry.get("urls", [])],
                    "profile_url": entry.get("profileUrl"),
                    "thumbnail": entry.get("thumbnailUrl"),
                }
    except Exception:
        pass
    return {"found": False}


# ─────────────────────────────────────────────
# Username pattern analysis
# ─────────────────────────────────────────────
def analyse_username(username):
    analysis = {
        "length": len(username),
        "has_numbers": bool(re.search(r"\d", username)),
        "has_underscores": "_" in username,
        "has_dots": "." in username,
        "has_hyphens": "-" in username,
        "all_lowercase": username.islower(),
        "possible_birth_year": None,
        "common_suffix_pattern": None,
    }
    # Check for embedded year
    years = re.findall(r"(19[6-9]\d|20[0-2]\d)", username)
    if years:
        analysis["possible_birth_year"] = years[0]
    # Suffix patterns
    suffixes = re.findall(r"(\d{2,4})$", username)
    if suffixes:
        analysis["common_suffix_pattern"] = suffixes[0]
    return analysis


# ─────────────────────────────────────────────
# Main scan orchestrator
# ─────────────────────────────────────────────
async def run_scan(username, email=None):
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            check_platform(session, name, cfg, username)
            for name, cfg in PLATFORMS.items()
        ]
        if email:
            tasks.append(check_gravatar(session, email))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    platform_results = []
    gravatar = None
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            continue
        if isinstance(r, dict) and "platform" in r:
            platform_results.append(r)
        elif isinstance(r, dict) and "found" in r and "display_name" in r:
            gravatar = r

    found = [p for p in platform_results if p["found"]]
    not_found = [p for p in platform_results if not p["found"] and not p["error"]]
    errors = [p for p in platform_results if p["error"]]

    # Build linked data map
    linked_data = {}
    for p in found:
        d = p.get("data", {})
        for key in ["email", "twitter_username", "github_username", "blog", "website_url", "location", "name", "bio"]:
            if d.get(key):
                linked_data.setdefault(key, [])
                linked_data[key].append({"source": p["platform"], "value": d[key]})

    return {
        "query": {
            "username": username,
            "email": email,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platforms_checked": len(platform_results),
        },
        "summary": {
            "found_count": len(found),
            "not_found_count": len(not_found),
            "error_count": len(errors),
            "score": round((len(found) / max(len(platform_results), 1)) * 100, 1),
        },
        "username_analysis": analyse_username(username),
        "platforms_found": found,
        "platforms_not_found": not_found,
        "platforms_error": errors,
        "linked_data": linked_data,
        "gravatar": gravatar,
    }


# ─────────────────────────────────────────────
# Flask routes
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip() or None

    if not username:
        return jsonify({"error": "Username is required"}), 400
    if not re.match(r"^[a-zA-Z0-9._\-]{1,50}$", username):
        return jsonify({"error": "Invalid username format"}), 400

    result = asyncio.run(run_scan(username, email))
    return jsonify(result)


@app.route("/api/platforms", methods=["GET"])
def list_platforms():
    return jsonify(
        [
            {"name": n, "url_template": v["url"], "category": v["category"], "icon": v["icon"]}
            for n, v in PLATFORMS.items()
        ]
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
