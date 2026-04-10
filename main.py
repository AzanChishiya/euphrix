"""
OSINT Username Intelligence Tool v3 — SSE Streaming Edition
──────────────────────────────────────────────────────────
• Real-time Server-Sent Events: results appear as found, not all at once
• ThreadPoolExecutor: 30 concurrent checks, massive speed boost
• Rotating User-Agents + client hint headers
• Body-pattern verification (not just HTTP status)
• Google Dork URL generation with Bing + DuckDuckGo
• Heartbeat keep-alive to prevent connection drops
• Zero timeout UX: server talks to client the whole time
"""

import json
import time
import re
import random
import queue
from datetime import datetime, timezone
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor

import requests as http
import urllib3
from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context
from flask_cors import CORS

# Suppress SSL verification warnings (we use verify=False for speed/compatibility)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# ══════════════════════════════════════════════════════════════════
# User-Agent rotation pool — mix of Chrome, Firefox, Safari, Edge
# ══════════════════════════════════════════════════════════════════
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
]


def get_headers():
    """Return a randomised, realistic browser header set."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://www.google.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-User": "?1",
    }


# ══════════════════════════════════════════════════════════════════
# Platform registry
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
        "api": None,
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
    "HackerOne": {
        "url": "https://hackerone.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Page not found",
        "confidence": "medium",
        "category": "Dev",
        "icon": "🔐",
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
        "body_must": "tgme_page_title",
        "body_must_not": None,
        "confidence": "high",
        "category": "Messaging",
        "icon": "✈️",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Sorry, nobody on Reddit goes by that name.",
        "confidence": "high",
        "category": "Forums",
        "icon": "🟠",
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
    "Ko-fi": {
        "url": "https://ko-fi.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_must": None,
        "body_must_not": "Page not found",
        "confidence": "medium",
        "category": "Creative",
        "icon": "☕",
    },
}

# ══════════════════════════════════════════════════════════════════
# Google Dork templates — grouped, with Google + Bing + DDG links
# ══════════════════════════════════════════════════════════════════
DORK_TEMPLATES = [
    # Identity & Presence
    {
        "label": "Exact username across all sites",
        "desc": "Every page Google has indexed containing this exact username",
        "query": '"{username}"',
        "icon": "🌐",
        "group": "Identity & Presence",
    },
    {
        "label": "Username on major social platforms",
        "desc": "Profile pages on Twitter, Instagram, Facebook and TikTok",
        "query": '"{username}" site:twitter.com OR site:instagram.com OR site:facebook.com OR site:tiktok.com',
        "icon": "👤",
        "group": "Identity & Presence",
    },
    {
        "label": "Username on Mastodon & alternatives",
        "desc": "Fediverse and decentralised social media presence",
        "query": '"{username}" site:mastodon.social OR site:threads.net OR site:bsky.app',
        "icon": "🐘",
        "group": "Identity & Presence",
    },
    # Professional & Code
    {
        "label": "Username on GitHub",
        "desc": "Code repositories, gists, and contributions",
        "query": 'site:github.com "{username}"',
        "icon": "💻",
        "group": "Professional & Code",
    },
    {
        "label": "Username on LinkedIn",
        "desc": "Professional profile, job history, connections",
        "query": 'site:linkedin.com "{username}"',
        "icon": "💼",
        "group": "Professional & Code",
    },
    {
        "label": "Username on dev communities",
        "desc": "Stack Overflow, HackerNews, Dev.to activity",
        "query": '"{username}" site:stackoverflow.com OR site:news.ycombinator.com OR site:dev.to',
        "icon": "🛠️",
        "group": "Professional & Code",
    },
    # Contact & Location
    {
        "label": "Username + email clues",
        "desc": "Publicly posted email addresses alongside this username",
        "query": '"{username}" email OR "contact me" OR "reach me"',
        "icon": "📧",
        "group": "Contact & Location",
    },
    {
        "label": "Username + location mentions",
        "desc": "Posts or profiles where a location is mentioned",
        "query": '"{username}" location OR city OR country OR "based in" OR "from"',
        "icon": "📍",
        "group": "Contact & Location",
    },
    {
        "label": "Username + phone or contact info",
        "desc": "Publicly listed contact details alongside this username",
        "query": '"{username}" "phone" OR "whatsapp" OR "telegram" OR "discord"',
        "icon": "📞",
        "group": "Contact & Location",
    },
    # Documents & Media
    {
        "label": "Username + resume or CV",
        "desc": "Publicly posted resumes, CVs, and portfolios",
        "query": '"{username}" resume OR CV OR portfolio filetype:pdf',
        "icon": "📄",
        "group": "Documents & Media",
    },
    {
        "label": "Username image search",
        "desc": "Profile pictures and avatars labelled with this username",
        "query": '"{username}" profile picture OR avatar OR "profile photo"',
        "icon": "🖼️",
        "group": "Documents & Media",
    },
    {
        "label": "Username in news articles",
        "desc": "News coverage and press mentions",
        "query": '"{username}" site:news.google.com OR inurl:article OR site:medium.com',
        "icon": "📰",
        "group": "Documents & Media",
    },
    # Forums & Pastes
    {
        "label": "Username on pastebin sites",
        "desc": "Pastes that mention or are attributed to this username",
        "query": '"{username}" site:pastebin.com OR site:paste.ee OR site:hastebin.com',
        "icon": "📋",
        "group": "Forums & Pastes",
    },
    {
        "label": "Username on Reddit and forums",
        "desc": "Forum posts, threads, and discussions",
        "query": '"{username}" site:reddit.com OR site:quora.com OR site:stackoverflow.com',
        "icon": "💬",
        "group": "Forums & Pastes",
    },
]


# ══════════════════════════════════════════════════════════════════
# Synchronous platform checker (runs in thread pool workers)
# ══════════════════════════════════════════════════════════════════
def check_platform_sync(name, cfg, username, timeout=12):
    """Check a single platform synchronously. Safe to call from any thread."""
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
        resp = http.get(
            url,
            headers=get_headers(),
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        elapsed = int((time.monotonic() - t0) * 1000)
        result["response_time_ms"] = elapsed
        result["http_status"] = resp.status_code

        # Explicit 404 or other not-found codes
        if resp.status_code in cfg["not_found_codes"]:
            result["found"] = False
            return result

        # Any other client/server error
        if resp.status_code >= 400:
            result["found"] = False
            return result

        body = resp.text

        # body_must_not: phrase signals "not found" disguised as 200
        if cfg.get("body_must_not") and cfg["body_must_not"].lower() in body.lower():
            result["found"] = False
            result["confidence"] = "high"  # confirmed by body text
            return result

        # body_must: phrase must be present for a real match
        if cfg.get("body_must"):
            if cfg["body_must"].lower() in body.lower():
                result["found"] = True
                result["confidence"] = "high"
            else:
                result["found"] = False
            return result

        # No body pattern — rely on status code (medium confidence)
        result["found"] = True

        # Fetch optional public API data
        if cfg.get("api") and result["found"]:
            api_url = cfg["api"].replace("{u}", username)
            result["data"] = fetch_api_data_sync(api_url, name)

    except http.exceptions.Timeout:
        result["error"] = "timeout"
    except http.exceptions.ConnectionError:
        result["error"] = "connection_refused"
    except http.exceptions.TooManyRedirects:
        result["error"] = "too_many_redirects"
    except Exception as e:
        result["error"] = type(e).__name__

    return result


def fetch_api_data_sync(api_url, platform_name):
    """Fetch supplementary public API data for a found profile."""
    try:
        resp = http.get(
            api_url,
            headers={**get_headers(), "Accept": "application/json"},
            timeout=8,
            verify=False,
        )
        if resp.status_code == 200:
            raw = resp.json()
            return parse_api_data(platform_name, raw)
    except Exception:
        pass
    return {}


def parse_api_data(platform, raw):
    """Extract useful fields from public API responses."""
    if platform == "GitHub":
        return {k: raw.get(k) for k in [
            "name", "bio", "location", "company", "blog",
            "public_repos", "followers", "following",
            "created_at", "avatar_url", "email", "twitter_username",
        ] if raw.get(k) is not None}

    if platform == "Chess.com":
        return {k: raw.get(k) for k in [
            "username", "name", "title", "status", "country",
            "location", "joined", "last_online", "followers",
        ] if raw.get(k) is not None}

    if platform == "Dailymotion":
        return {k: raw.get(k) for k in [
            "screenname", "description", "city", "country",
            "videocount", "fans", "following",
        ] if raw.get(k) is not None}

    if platform == "GitLab":
        if isinstance(raw, list) and raw:
            u = raw[0]
            return {k: u.get(k) for k in [
                "name", "username", "bio", "location", "website_url", "created_at",
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
    if re.match(r"^[A-Za-z]+[._]?[A-Za-z]+$", username) and not any(c.isdigit() for c in username):
        analysis["possible_real_name"] = True
    return analysis


# ══════════════════════════════════════════════════════════════════
# Generate dork URLs — returns google + bing + ddg per dork
# ══════════════════════════════════════════════════════════════════
def build_dork_urls(username):
    results = []
    for d in DORK_TEMPLATES:
        q = d["query"].replace("{username}", username)
        results.append({
            "label": d["label"],
            "desc": d["desc"],
            "icon": d["icon"],
            "group": d["group"],
            "query": q,
            "google": f"https://www.google.com/search?q={quote_plus(q)}",
            "bing": f"https://www.bing.com/search?q={quote_plus(q)}",
            "ddg": f"https://duckduckgo.com/?q={quote_plus(q)}",
        })
    return results


# ══════════════════════════════════════════════════════════════════
# Build cross-platform linked data from found profiles
# ══════════════════════════════════════════════════════════════════
def build_linked_data(found_list):
    linked = {}
    for p in found_list:
        d = p.get("data", {})
        for key in ["email", "twitter_username", "blog", "location",
                    "name", "bio", "website_url", "country", "city"]:
            if d.get(key):
                linked.setdefault(key, [])
                linked[key].append({"source": p["platform"], "value": d[key]})
    return linked


# ══════════════════════════════════════════════════════════════════
# SSE Streaming scan — the main endpoint
# ══════════════════════════════════════════════════════════════════
@app.route("/api/stream", methods=["POST"])
def stream_scan():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()

    if not username:
        return jsonify({"error": "Username is required"}), 400
    if not re.match(r"^[a-zA-Z0-9._\-]{1,50}$", username):
        return jsonify({"error": "Invalid username — use only letters, numbers, dots, hyphens, underscores"}), 400

    def generate():
        result_queue = queue.Queue()
        total = len(PLATFORMS)
        completed = [0]
        found_list = []
        not_found_list = []
        error_list = []

        def worker(name, cfg):
            """Thread worker: check one platform and enqueue result."""
            try:
                r = check_platform_sync(name, cfg, username)
            except Exception as exc:
                r = {
                    "platform": name,
                    "url": cfg["url"].replace("{u}", username),
                    "found": False,
                    "confidence": cfg["confidence"],
                    "category": cfg["category"],
                    "icon": cfg["icon"],
                    "data": {},
                    "error": type(exc).__name__,
                    "response_time_ms": None,
                    "http_status": None,
                }
            result_queue.put(r)

        # Fire all workers concurrently — 30 threads
        executor = ThreadPoolExecutor(max_workers=30)
        for name, cfg in PLATFORMS.items():
            executor.submit(worker, name, cfg)
        executor.shutdown(wait=False)

        # Stream results as they arrive from the queue
        deadline = time.time() + 50  # hard 50s ceiling
        while completed[0] < total and time.time() < deadline:
            try:
                result = result_queue.get(timeout=1.0)
                completed[0] += 1

                if result.get("found"):
                    found_list.append(result)
                elif result.get("error"):
                    error_list.append(result)
                else:
                    not_found_list.append(result)

                event_data = {
                    "type": "result",
                    "data": result,
                    "progress": completed[0],
                    "total": total,
                }
                yield f"data: {json.dumps(event_data)}\n\n"

            except queue.Empty:
                # Send heartbeat comment — keeps connection alive, client ignores it
                yield ": heartbeat\n\n"

        # Confidence breakdown
        conf_counts = {"high": 0, "medium": 0, "low": 0}
        for p in found_list:
            key = p.get("confidence", "medium")
            conf_counts[key] = conf_counts.get(key, 0) + 1

        # Final "complete" event with all summary data
        complete_event = {
            "type": "complete",
            "query": {
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "platforms_checked": completed[0],
            },
            "summary": {
                "found_count": len(found_list),
                "not_found_count": len(not_found_list),
                "error_count": len(error_list),
                "score": round(len(found_list) / max(completed[0], 1) * 100, 1),
                "confidence_breakdown": conf_counts,
            },
            "username_analysis": analyse_username(username),
            "linked_data": build_linked_data(found_list),
            "dork_urls": build_dork_urls(username),
            "platforms_not_found": not_found_list,
            "platforms_error": error_list,
        }
        yield f"data: {json.dumps(complete_event)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ══════════════════════════════════════════════════════════════════
# Other Flask routes
# ══════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/platforms", methods=["GET"])
def list_platforms():
    return jsonify([
        {
            "name": n,
            "url_template": v["url"],
            "category": v["category"],
            "icon": v["icon"],
            "confidence": v["confidence"],
        }
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
