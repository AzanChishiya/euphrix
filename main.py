"""
OSINT Username Intelligence Tool v2 — Ethical Public-Data Scanner
─────────────────────────────────────────────────────────────────
• Only checks publicly accessible profile URLs (no auth required)
• Body-pattern matching for high-confidence results (not just HTTP status)
• Official public APIs only (GitHub, YouTube Data API public endpoints)
• Google Dork URL generation (opens search — no scraping Google)
• No credential harvesting, no auth-system abuse, no ToS violations
"""

import asyncio
import aiohttp
import json
import time
import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import quote_plus
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# ══════════════════════════════════════════════════════════════════
# Platform registry
# Each entry has:
#   url           — public profile URL template
#   api           — optional public API endpoint
#   not_found_codes — HTTP codes that mean "no account"
#   body_must      — string that MUST appear in body if account exists
#   body_must_not  — string that means 404-in-disguise (200 but user gone)
#   confidence     — "high" if body pattern checked, "medium" otherwise
#   category       — display grouping
#   icon           — emoji
# ══════════════════════════════════════════════════════════════════
PLATFORMS = {
    # ── Social mega-platforms ─────────────────────────────────────
    "Instagram": {
        "url": "https://www.instagram.com/{u}/",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Sorry, this page isn't available.",
        "confidence": "high",
        "category": "Social",
        "icon": "📸",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "couldn't find this account",
        "confidence": "high",
        "category": "Social",
        "icon": "🎵",
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": '"username":',
        "body_must_not": None,
        "confidence": "high",
        "category": "Social",
        "icon": "👻",
    },
    "Facebook": {
        "url": "https://www.facebook.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "This content isn't available",
        "confidence": "medium",
        "category": "Social",
        "icon": "🔵",
    },
    "Twitter/X": {
        "url": "https://twitter.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "This account doesn't exist",
        "confidence": "medium",
        "category": "Social",
        "icon": "𝕏",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{u}/",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "📌",
    },
    "Tumblr": {
        "url": "https://{u}.tumblr.com",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "There's nothing here.",
        "confidence": "high",
        "category": "Social",
        "icon": "🟦",
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "🐘",
    },
    "Threads": {
        "url": "https://www.threads.net/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "🧵",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Page not found",
        "confidence": "medium",
        "category": "Professional",
        "icon": "💼",
    },

    # ── Video / Streaming ─────────────────────────────────────────
    "YouTube": {
        "url": "https://www.youtube.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "404 Not Found",
        "confidence": "medium",
        "category": "Video",
        "icon": "▶️",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{u}",
        "api": "https://api.twitch.tv/helix/users?login={u}",
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Video",
        "icon": "🟣",
    },
    "Vimeo": {
        "url": "https://vimeo.com/{u}",
        "api": "https://vimeo.com/api/oembed.json?url=https://vimeo.com/{u}",
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Video",
        "icon": "🎬",
    },
    "Dailymotion": {
        "url": "https://www.dailymotion.com/{u}",
        "api": "https://api.dailymotion.com/user/{u}",
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "high",
        "category": "Video",
        "icon": "📹",
    },

    # ── Dev & Code ────────────────────────────────────────────────
    "GitHub": {
        "url": "https://github.com/{u}",
        "api": "https://api.github.com/users/{u}",
        "not_found_codes": [404],
        "body_must": 'data-hovercard-type="user"',
        "body_must_not": None,
        "confidence": "high",
        "category": "Dev",
        "icon": "💻",
    },
    "GitLab": {
        "url": "https://gitlab.com/{u}",
        "api": "https://gitlab.com/api/v4/users?username={u}",
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "🦊",
    },
    "Stack Overflow": {
        "url": "https://stackoverflow.com/users/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Page Not Found",
        "confidence": "medium",
        "category": "Dev",
        "icon": "📚",
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "📦",
    },
    "PyPI": {
        "url": "https://pypi.org/user/{u}/",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "🐍",
    },
    "Replit": {
        "url": "https://replit.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Page not found",
        "confidence": "high",
        "category": "Dev",
        "icon": "♻️",
    },
    "Codepen": {
        "url": "https://codepen.io/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "🖊️",
    },

    # ── Music & Audio ─────────────────────────────────────────────
    "Spotify": {
        "url": "https://open.spotify.com/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Music",
        "icon": "🎧",
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "We can't find that user.",
        "confidence": "high",
        "category": "Music",
        "icon": "🔊",
    },
    "Last.fm": {
        "url": "https://www.last.fm/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "User not found",
        "confidence": "high",
        "category": "Music",
        "icon": "🎼",
    },

    # ── Gaming ────────────────────────────────────────────────────
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "The specified profile could not be found.",
        "confidence": "high",
        "category": "Gaming",
        "icon": "🎮",
    },
    "Roblox": {
        "url": "https://www.roblox.com/user.aspx?username={u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Gaming",
        "icon": "🧱",
    },
    "Chess.com": {
        "url": "https://www.chess.com/member/{u}",
        "api": "https://api.chess.com/pub/player/{u}",
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "high",
        "category": "Gaming",
        "icon": "♟️",
    },

    # ── Creative ──────────────────────────────────────────────────
    "Medium": {
        "url": "https://medium.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Page not found",
        "confidence": "high",
        "category": "Creative",
        "icon": "✍️",
    },
    "Behance": {
        "url": "https://www.behance.net/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "🎨",
    },
    "Dribbble": {
        "url": "https://dribbble.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Whoops, that page is gone.",
        "confidence": "high",
        "category": "Creative",
        "icon": "🏀",
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "🖼️",
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "📷",
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "📖",
    },

    # ── Messaging / Community ─────────────────────────────────────
    "Telegram": {
        "url": "https://t.me/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": 'tgme_page_title',
        "body_must_not": None,
        "confidence": "high",
        "category": "Messaging",
        "icon": "✈️",
    },
    "Discord (lookup)": {
        "url": "https://discord.com/users/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "low",
        "category": "Messaging",
        "icon": "🎙️",
    },

    # ── Q&A / Forums ──────────────────────────────────────────────
    "Quora": {
        "url": "https://www.quora.com/profile/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Forums",
        "icon": "❓",
    },

    # ── Shopping / Other ──────────────────────────────────────────
    "Etsy": {
        "url": "https://www.etsy.com/shop/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Shopping",
        "icon": "🛍️",
    },
    "Patreon": {
        "url": "https://www.patreon.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "🎁",
    },
}

# ══════════════════════════════════════════════════════════════════
# Google Dork templates — generates clickable search URLs only
# No scraping, no automated querying — user opens them in browser
# ══════════════════════════════════════════════════════════════════
DORK_TEMPLATES = [
    {
        "label": 'Exact username across all sites',
        "desc":  'Search every site Google has indexed for this username',
        "query": '"{username}"',
        "icon": "🌐",
    },
    {
        "label": 'Username + social profiles',
        "desc":  'Find profile pages mentioning this username',
        "query": '"{username}" site:twitter.com OR site:instagram.com OR site:facebook.com OR site:tiktok.com',
        "icon": "👤",
    },
    {
        "label": 'Username on GitHub',
        "desc":  'Find code, gists, and repos linked to this name',
        "query": 'site:github.com "{username}"',
        "icon": "💻",
    },
    {
        "label": 'Username + LinkedIn',
        "desc":  'Find professional profile if public',
        "query": 'site:linkedin.com "{username}"',
        "icon": "💼",
    },
    {
        "label": 'Username + email clues',
        "desc":  'Find publicly posted emails alongside this username',
        "query": '"{username}" email',
        "icon": "📧",
    },
    {
        "label": 'Username + location mentions',
        "desc":  'Find posts or profiles where location is mentioned',
        "query": '"{username}" location OR city OR country',
        "icon": "📍",
    },
    {
        "label": 'Username + resume / CV',
        "desc":  'Find publicly posted resumes or CVs',
        "query": '"{username}" resume OR CV OR portfolio filetype:pdf',
        "icon": "📄",
    },
    {
        "label": 'Username on pastebin sites',
        "desc":  'Find pastes that mention this username',
        "query": '"{username}" site:pastebin.com OR site:paste.ee OR site:ghostbin.co',
        "icon": "📋",
    },
    {
        "label": 'Username on forums & discussion boards',
        "desc":  'Find forum posts by or about this username',
        "query": '"{username}" site:reddit.com OR site:quora.com OR site:stackoverflow.com',
        "icon": "💬",
    },
    {
        "label": 'Username + phone or contact info',
        "desc":  'Find publicly listed contact info alongside username',
        "query": '"{username}" "phone" OR "contact" OR "reach me"',
        "icon": "📞",
    },
    {
        "label": 'Username in news articles',
        "desc":  'Find news coverage mentioning this username',
        "query": '"{username}" site:news.google.com OR inurl:article',
        "icon": "📰",
    },
    {
        "label": 'Username image search',
        "desc":  'Find images labelled with this username',
        "query": '"{username}" profile picture OR avatar',
        "icon": "🖼️",
    },
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# ══════════════════════════════════════════════════════════════════
# Async platform checker
# ══════════════════════════════════════════════════════════════════
async def check_platform(session, name, cfg, username, timeout=12):
    url = cfg["url"].replace("{u}", username)
    result = {
        "platform": name,
        "url": url,
        "found": False,
        "confidence": cfg["confidence"],
        "category": cfg["category"],
        "icon": cfg["icon"],
        "data": {},
        "error": None,
        "response_time_ms": None,
        "http_status": None,
    }
    try:
        t0 = time.monotonic()
        async with session.get(
            url, headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True, ssl=False
        ) as resp:
            elapsed = int((time.monotonic() - t0) * 1000)
            result["response_time_ms"] = elapsed
            result["http_status"] = resp.status

            if resp.status in cfg["not_found_codes"]:
                result["found"] = False
                return result

            if resp.status >= 400:
                result["found"] = False
                return result

            # Read body for pattern matching
            try:
                body = await resp.text(encoding="utf-8", errors="ignore")
            except Exception:
                body = ""

            # body_must_not — if this phrase appears, it's a "not found" disguised as 200
            if cfg.get("body_must_not") and cfg["body_must_not"].lower() in body.lower():
                result["found"] = False
                result["confidence"] = "high"  # we confirmed by body
                return result

            # body_must — must be present for a real match
            if cfg.get("body_must"):
                if cfg["body_must"].lower() in body.lower():
                    result["found"] = True
                    result["confidence"] = "high"
                else:
                    result["found"] = False
                return result

            # No body pattern — rely on status code alone (medium confidence)
            result["found"] = True

        # Fetch public API data if available
        if cfg.get("api"):
            result["data"] = await fetch_api_data(session, cfg["api"].replace("{u}", username), name)

    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except aiohttp.ClientConnectorError:
        result["error"] = "connection refused"
    except Exception as e:
        result["error"] = type(e).__name__
    return result


async def fetch_api_data(session, api_url, platform_name):
    try:
        async with session.get(
            api_url,
            headers={**HEADERS, "Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(total=8),
            ssl=False,
        ) as r:
            if r.status == 200:
                raw = await r.json(content_type=None)
                return parse_api_data(platform_name, raw)
    except Exception:
        pass
    return {}


def parse_api_data(platform, raw):
    if platform == "GitHub":
        return {k: raw.get(k) for k in [
            "name","bio","location","company","blog",
            "public_repos","followers","following",
            "created_at","avatar_url","email","twitter_username"
        ] if raw.get(k) is not None}

    if platform == "Chess.com":
        return {k: raw.get(k) for k in [
            "username","name","title","status","country",
            "location","joined","last_online","followers"
        ] if raw.get(k) is not None}

    if platform == "Dailymotion":
        return {k: raw.get(k) for k in [
            "screenname","description","city","country",
            "videocount","fans","following"
        ] if raw.get(k) is not None}

    if platform == "GitLab":
        if isinstance(raw, list) and raw:
            u = raw[0]
            return {k: u.get(k) for k in [
                "name","username","bio","location","website_url","created_at"
            ] if u.get(k) is not None}
    return {}


# ══════════════════════════════════════════════════════════════════
# Username pattern analysis
# ══════════════════════════════════════════════════════════════════
def analyse_username(username):
    analysis = {
        "length": len(username),
        "has_numbers": bool(re.search(r"\d", username)),
        "has_underscores": "_" in username,
        "has_dots": "." in username,
        "has_hyphens": "-" in username,
        "all_lowercase": username.islower(),
        "all_uppercase": username.isupper(),
        "mixed_case": not username.islower() and not username.isupper(),
        "possible_birth_year": None,
        "common_suffix_digits": None,
        "possible_real_name": False,
    }
    years = re.findall(r"(19[6-9]\d|20[0-2]\d)", username)
    if years:
        analysis["possible_birth_year"] = years[0]
    suffix = re.findall(r"(\d{2,4})$", username)
    if suffix:
        analysis["common_suffix_digits"] = suffix[0]
    # Looks like FirstLastName or first.last pattern
    if re.match(r"^[A-Za-z]+[._]?[A-Za-z]+$", username) and not any(c.isdigit() for c in username):
        analysis["possible_real_name"] = True
    return analysis


# ══════════════════════════════════════════════════════════════════
# Generate dork URLs
# ══════════════════════════════════════════════════════════════════
def build_dork_urls(username):
    results = []
    for d in DORK_TEMPLATES:
        q = d["query"].replace("{username}", username)
        results.append({
            "label": d["label"],
            "desc":  d["desc"],
            "icon":  d["icon"],
            "query": q,
            "url":   f"https://www.google.com/search?q={quote_plus(q)}",
            "bing":  f"https://www.bing.com/search?q={quote_plus(q)}",
        })
    return results


# ══════════════════════════════════════════════════════════════════
# Main scan
# ══════════════════════════════════════════════════════════════════
async def run_scan(username):
    connector = aiohttp.TCPConnector(limit=40, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            check_platform(session, name, cfg, username)
            for name, cfg in PLATFORMS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    platform_results = []
    for r in results:
        if isinstance(r, dict) and "platform" in r:
            platform_results.append(r)

    found     = [p for p in platform_results if p["found"]]
    not_found = [p for p in platform_results if not p["found"] and not p["error"]]
    errors    = [p for p in platform_results if p["error"]]

    # Cross-platform data linkage
    linked_data = {}
    for p in found:
        d = p.get("data", {})
        for key in ["email","twitter_username","blog","location","name","bio","website_url","country","city"]:
            if d.get(key):
                linked_data.setdefault(key, [])
                linked_data[key].append({"source": p["platform"], "value": d[key]})

    # Confidence breakdown
    conf_counts = {"high": 0, "medium": 0, "low": 0}
    for p in found:
        conf_counts[p["confidence"]] = conf_counts.get(p["confidence"], 0) + 1

    return {
        "query": {
            "username": username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platforms_checked": len(platform_results),
        },
        "summary": {
            "found_count":     len(found),
            "not_found_count": len(not_found),
            "error_count":     len(errors),
            "score":           round(len(found) / max(len(platform_results), 1) * 100, 1),
            "confidence_breakdown": conf_counts,
        },
        "username_analysis":  analyse_username(username),
        "platforms_found":    found,
        "platforms_not_found": not_found,
        "platforms_error":    errors,
        "linked_data":        linked_data,
        "dork_urls":          build_dork_urls(username),
    }


# ══════════════════════════════════════════════════════════════════
# Flask routes
# ══════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if not re.match(r"^[a-zA-Z0-9._\-]{1,50}$", username):
        return jsonify({"error": "Invalid username — use only letters, numbers, dots, hyphens, underscores"}), 400
    result = asyncio.run(run_scan(username))
    return jsonify(result)

@app.route("/api/platforms", methods=["GET"])
def list_platforms():
    return jsonify([
        {"name": n, "url_template": v["url"], "category": v["category"],
         "icon": v["icon"], "confidence": v["confidence"]}
        for n, v in PLATFORMS.items()
    ])

@app.route("/api/dorks", methods=["POST"])
def dorks():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Username required"}), 400
    return jsonify(build_dork_urls(username))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
