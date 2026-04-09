"""
OSINT Scanner v3 — Production Backend
──────────────────────────────────────
Ethical: public URLs + official open APIs only.
Anti-detection: rotating User-Agents, per-domain delays, realistic headers,
                chunked concurrency so we don't blast 40 requests at once.
"""

import asyncio
import aiohttp
import json
import time
import re
import random
import hashlib
from datetime import datetime, timezone
from urllib.parse import quote_plus
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# ══════════════════════════════════════════════════════════════════════
# Rotating User-Agents — realistic browser strings
# ══════════════════════════════════════════════════════════════════════
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
]

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Cache-Control": "max-age=0",
    }

# ══════════════════════════════════════════════════════════════════════
# Platform Registry
# Fields:
#   url           — profile URL ({u} = username)
#   api           — optional public JSON API
#   not_found_codes — HTTP codes = no account
#   body_miss     — text in body that means "not found" (200 but gone)
#   body_hit      — text that MUST be in body for confirmed match
#   confidence    — base confidence level
#   category / icon
#   note          — optional user-facing note
# ══════════════════════════════════════════════════════════════════════
PLATFORMS = {

    # ── Social ──────────────────────────────────────────────────────
    "Instagram": {
        "url": "https://www.instagram.com/{u}/",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Sorry, this page isn't available.",
        "body_hit": None,
        "confidence": "high",
        "category": "Social",
        "icon": "📸",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "couldn't find this account",
        "body_hit": None,
        "confidence": "high",
        "category": "Social",
        "icon": "🎵",
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": '"username":"',
        "confidence": "high",
        "category": "Social",
        "icon": "👻",
    },
    "Facebook": {
        "url": "https://www.facebook.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "This content isn't available right now",
        "body_hit": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "🔵",
    },
    "Twitter / X": {
        "url": "https://twitter.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "This account doesn't exist",
        "body_hit": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "𝕏",
    },
    "Threads": {
        "url": "https://www.threads.net/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "🧵",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{u}/",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "📌",
    },
    "Tumblr": {
        "url": "https://{u}.tumblr.com",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "There's nothing here.",
        "body_hit": None,
        "confidence": "high",
        "category": "Social",
        "icon": "🟦",
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "🐘",
    },
    "Bluesky": {
        "url": "https://bsky.app/profile/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Social",
        "icon": "🦋",
    },

    # ── Professional ─────────────────────────────────────────────────
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Page not found",
        "body_hit": None,
        "confidence": "medium",
        "category": "Professional",
        "icon": "💼",
    },
    "AngelList": {
        "url": "https://angel.co/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Professional",
        "icon": "👼",
    },

    # ── Video / Streaming ────────────────────────────────────────────
    "YouTube": {
        "url": "https://www.youtube.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "This page isn't available",
        "body_hit": None,
        "confidence": "medium",
        "category": "Video",
        "icon": "▶️",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Video",
        "icon": "🟣",
    },
    "Vimeo": {
        "url": "https://vimeo.com/{u}",
        "api": "https://vimeo.com/api/oembed.json?url=https://vimeo.com/{u}",
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "high",
        "category": "Video",
        "icon": "🎬",
    },
    "Dailymotion": {
        "url": "https://www.dailymotion.com/{u}",
        "api": "https://api.dailymotion.com/user/{u}",
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "high",
        "category": "Video",
        "icon": "📹",
    },
    "Rumble": {
        "url": "https://rumble.com/c/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Video",
        "icon": "🎥",
    },

    # ── Dev & Code ───────────────────────────────────────────────────
    "GitHub": {
        "url": "https://github.com/{u}",
        "api": "https://api.github.com/users/{u}",
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": 'data-hovercard-type="user"',
        "confidence": "high",
        "category": "Dev",
        "icon": "💻",
    },
    "GitLab": {
        "url": "https://gitlab.com/{u}",
        "api": "https://gitlab.com/api/v4/users?username={u}",
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "🦊",
    },
    "Stack Overflow": {
        "url": "https://stackoverflow.com/users/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Page Not Found",
        "body_hit": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "📚",
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "📦",
    },
    "PyPI": {
        "url": "https://pypi.org/user/{u}/",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "🐍",
    },
    "Replit": {
        "url": "https://replit.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Page not found",
        "body_hit": None,
        "confidence": "high",
        "category": "Dev",
        "icon": "♻️",
    },
    "CodePen": {
        "url": "https://codepen.io/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Dev",
        "icon": "🖊️",
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{u}/",
        "api": "https://api.bitbucket.org/2.0/users/{u}",
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "high",
        "category": "Dev",
        "icon": "🪣",
    },

    # ── Music ────────────────────────────────────────────────────────
    "Spotify": {
        "url": "https://open.spotify.com/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Music",
        "icon": "🎧",
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "We can't find that user.",
        "body_hit": None,
        "confidence": "high",
        "category": "Music",
        "icon": "🔊",
    },
    "Last.fm": {
        "url": "https://www.last.fm/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "User not found",
        "body_hit": None,
        "confidence": "high",
        "category": "Music",
        "icon": "🎼",
    },
    "Bandcamp": {
        "url": "https://bandcamp.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Music",
        "icon": "🎸",
    },

    # ── Gaming ───────────────────────────────────────────────────────
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "The specified profile could not be found.",
        "body_hit": None,
        "confidence": "high",
        "category": "Gaming",
        "icon": "🎮",
    },
    "Roblox": {
        "url": "https://www.roblox.com/user.aspx?username={u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Gaming",
        "icon": "🧱",
    },
    "Chess.com": {
        "url": "https://www.chess.com/member/{u}",
        "api": "https://api.chess.com/pub/player/{u}",
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "high",
        "category": "Gaming",
        "icon": "♟️",
    },
    "Minecraft": {
        "url": "https://namemc.com/profile/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Profile Not Found",
        "body_hit": None,
        "confidence": "high",
        "category": "Gaming",
        "icon": "⛏️",
    },

    # ── Creative ─────────────────────────────────────────────────────
    "Medium": {
        "url": "https://medium.com/@{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Page not found",
        "body_hit": None,
        "confidence": "high",
        "category": "Creative",
        "icon": "✍️",
    },
    "Behance": {
        "url": "https://www.behance.net/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "🎨",
    },
    "Dribbble": {
        "url": "https://dribbble.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": "Whoops, that page is gone.",
        "body_hit": None,
        "confidence": "high",
        "category": "Creative",
        "icon": "🏀",
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "🖼️",
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "📷",
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "📖",
    },
    "Patreon": {
        "url": "https://www.patreon.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "🎁",
    },
    "Ko-fi": {
        "url": "https://ko-fi.com/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Creative",
        "icon": "☕",
    },

    # ── Messaging / Community ────────────────────────────────────────
    "Telegram": {
        "url": "https://t.me/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": "tgme_page_title",
        "confidence": "high",
        "category": "Messaging",
        "icon": "✈️",
    },

    # ── Q&A / Forums ─────────────────────────────────────────────────
    "Quora": {
        "url": "https://www.quora.com/profile/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Forums",
        "icon": "❓",
    },

    # ── Shopping ─────────────────────────────────────────────────────
    "Etsy": {
        "url": "https://www.etsy.com/shop/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Shopping",
        "icon": "🛍️",
    },
    "eBay": {
        "url": "https://www.ebay.com/usr/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Shopping",
        "icon": "🛒",
    },

    # ── Portfolio / Bio links ────────────────────────────────────────
    "About.me": {
        "url": "https://about.me/{u}",
        "api": None,
        "not_found_codes": [404],
        "body_miss": None,
        "body_hit": None,
        "confidence": "medium",
        "category": "Portfolio",
        "icon": "👤",
    },
}

# ══════════════════════════════════════════════════════════════════════
# Google Dork templates (22 total)
# ══════════════════════════════════════════════════════════════════════
DORK_TEMPLATES = [
    # Identity
    {
        "group": "Identity",
        "label": "Exact username — all sites",
        "desc":  "Search every page Google has indexed for this exact username string.",
        "query": '"{username}"',
        "icon":  "🌐",
    },
    {
        "group": "Identity",
        "label": "Username as a real name variation",
        "desc":  "Find pages that treat the username as a person's actual name.",
        "query": '"{username}" person OR profile OR "about me" OR bio',
        "icon":  "🪪",
    },
    {
        "group": "Identity",
        "label": "Username + website or blog",
        "desc":  "Find personal sites, blogs, or portfolios linked to this name.",
        "query": '"{username}" site:wordpress.com OR site:blogger.com OR site:substack.com OR site:ghost.io',
        "icon":  "🌍",
    },

    # Social
    {
        "group": "Social",
        "label": "Major social platforms",
        "desc":  "Search Instagram, TikTok, Twitter/X, Facebook and Snapchat at once.",
        "query": '"{username}" site:instagram.com OR site:tiktok.com OR site:twitter.com OR site:facebook.com OR site:snapchat.com',
        "icon":  "👥",
    },
    {
        "group": "Social",
        "label": "LinkedIn profile",
        "desc":  "Find any public LinkedIn profile page for this username.",
        "query": 'site:linkedin.com/in/ "{username}"',
        "icon":  "💼",
    },
    {
        "group": "Social",
        "label": "YouTube channel",
        "desc":  "Find public YouTube channels with this name or handle.",
        "query": 'site:youtube.com "{username}" channel OR "@{username}"',
        "icon":  "▶️",
    },
    {
        "group": "Social",
        "label": "Telegram public channel or group",
        "desc":  "Find public Telegram channels, bots, or groups linked to this username.",
        "query": 'site:t.me "{username}" OR "t.me/{username}"',
        "icon":  "✈️",
    },

    # Dev
    {
        "group": "Dev",
        "label": "GitHub — code, repos, gists",
        "desc":  "Find all public GitHub activity: repos, gists, issues, comments.",
        "query": 'site:github.com "{username}"',
        "icon":  "💻",
    },
    {
        "group": "Dev",
        "label": "Stack Overflow / Dev forums",
        "desc":  "Find developer forum activity on Stack Overflow, Reddit r/programming, etc.",
        "query": '"{username}" site:stackoverflow.com OR site:dev.to OR site:hashnode.com',
        "icon":  "📚",
    },

    # Contact clues
    {
        "group": "Contact",
        "label": "Email address clues",
        "desc":  "Find publicly posted email addresses alongside this username in any context.",
        "query": '"{username}" "@gmail.com" OR "@yahoo.com" OR "@outlook.com" OR "@hotmail.com" OR "email"',
        "icon":  "📧",
    },
    {
        "group": "Contact",
        "label": "Phone number mentions",
        "desc":  "Find publicly shared phone numbers associated with this username.",
        "query": '"{username}" "phone" OR "tel" OR "call me" OR "whatsapp" OR "contact"',
        "icon":  "📞",
    },
    {
        "group": "Contact",
        "label": "Username in forums & discussion boards",
        "desc":  "Find forum posts, threads, or comments by or about this username.",
        "query": '"{username}" site:reddit.com OR site:quora.com OR site:forums.com OR inurl:forum',
        "icon":  "💬",
    },

    # Location
    {
        "group": "Location",
        "label": "Location mentions",
        "desc":  "Find posts, bios, or profiles where this username is paired with a location.",
        "query": '"{username}" location OR city OR country OR "lives in" OR "based in" OR "from"',
        "icon":  "📍",
    },
    {
        "group": "Location",
        "label": "Username + timezone or region",
        "desc":  "Find references to a timezone, region, or country next to this username.",
        "query": '"{username}" GMT OR UTC OR timezone OR region OR state OR province',
        "icon":  "🗺️",
    },

    # Files & Documents
    {
        "group": "Documents",
        "label": "Public resume or CV (PDF)",
        "desc":  "Find publicly accessible PDF resumes or CVs associated with this name.",
        "query": '"{username}" resume OR CV OR curriculum filetype:pdf',
        "icon":  "📄",
    },
    {
        "group": "Documents",
        "label": "Public documents (DOCX, PPTX)",
        "desc":  "Find public Microsoft Office files that mention this username.",
        "query": '"{username}" filetype:docx OR filetype:pptx OR filetype:xlsx',
        "icon":  "📑",
    },

    # Pastes & Leaks
    {
        "group": "Pastes",
        "label": "Username on paste sites",
        "desc":  "Find any paste that mentions this username on Pastebin and similar sites.",
        "query": '"{username}" site:pastebin.com OR site:paste.ee OR site:hastebin.com OR site:dpaste.com',
        "icon":  "📋",
    },
    {
        "group": "Pastes",
        "label": "Username in data breach mentions",
        "desc":  "Find any public mention of this username in breach-related discussions.",
        "query": '"{username}" "data breach" OR "leaked" OR "exposed" -site:haveibeenpwned.com',
        "icon":  "⚠️",
    },

    # News & Media
    {
        "group": "Media",
        "label": "News articles mentioning username",
        "desc":  "Find news articles, press releases, or media coverage of this username.",
        "query": '"{username}" site:news.google.com OR inurl:news OR "press release" OR "reported"',
        "icon":  "📰",
    },
    {
        "group": "Media",
        "label": "Podcasts or interviews",
        "desc":  "Find podcasts, interviews, or spoken-word content featuring this name.",
        "query": '"{username}" podcast OR interview OR "guest on" OR "episode"',
        "icon":  "🎙️",
    },

    # Image / Avatar
    {
        "group": "Images",
        "label": "Profile pictures and avatars",
        "desc":  "Find images captioned, tagged, or described with this username.",
        "query": '"{username}" profile picture OR avatar OR "photo of" OR pfp',
        "icon":  "🖼️",
    },

    # Crypto / Web3
    {
        "group": "Web3",
        "label": "Crypto & Web3 presence",
        "desc":  "Find wallet addresses, NFT profiles, or crypto activity linked to this username.",
        "query": '"{username}" wallet OR ethereum OR bitcoin OR NFT OR "opensea" OR "crypto"',
        "icon":  "🪙",
    },
]


# ══════════════════════════════════════════════════════════════════════
# Chunked async scanner — avoids bursting all 45 requests at once
# ══════════════════════════════════════════════════════════════════════
CHUNK_SIZE = 8          # requests per chunk
CHUNK_DELAY = (0.4, 0.9)  # random sleep between chunks (seconds)
READ_BYTES  = 32_000    # max body bytes to read (avoid huge downloads)


async def check_platform(session, name, cfg, username, timeout=14):
    url = cfg["url"].replace("{u}", username)
    result = {
        "platform":        name,
        "url":             url,
        "found":           False,
        "confidence":      cfg["confidence"],
        "category":        cfg["category"],
        "icon":            cfg["icon"],
        "data":            {},
        "error":           None,
        "error_detail":    None,
        "response_time_ms": None,
        "http_status":     None,
    }
    try:
        await asyncio.sleep(random.uniform(0.05, 0.25))   # tiny per-request jitter
        t0 = time.monotonic()
        async with session.get(
            url,
            headers=get_headers(),
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=False,
        ) as resp:
            elapsed = int((time.monotonic() - t0) * 1000)
            result["response_time_ms"] = elapsed
            result["http_status"]      = resp.status

            if resp.status in cfg["not_found_codes"]:
                result["found"] = False
                return result
            if resp.status >= 400:
                result["found"] = False
                return result

            # Read partial body
            raw = b""
            async for chunk in resp.content.iter_chunked(4096):
                raw += chunk
                if len(raw) >= READ_BYTES:
                    break
            body = raw.decode("utf-8", errors="ignore").lower()

            # body_miss — 200 but "not found" text present → gone
            miss = cfg.get("body_miss")
            if miss and miss.lower() in body:
                result["found"]      = False
                result["confidence"] = "high"
                return result

            # body_hit — must be present to confirm
            hit = cfg.get("body_hit")
            if hit:
                if hit.lower() in body:
                    result["found"]      = True
                    result["confidence"] = "high"
                else:
                    result["found"] = False
                return result

            # No pattern → status-code match
            result["found"] = True

        # Enrich via public API
        api_tpl = cfg.get("api")
        if api_tpl and result["found"]:
            result["data"] = await fetch_api(session, api_tpl.replace("{u}", username), name)

    except asyncio.TimeoutError:
        result["error"]        = "timeout"
        result["error_detail"] = f"No response within {timeout}s"
    except aiohttp.ClientConnectorError as e:
        result["error"]        = "connection_failed"
        result["error_detail"] = "Could not reach server"
    except aiohttp.ServerDisconnectedError:
        result["error"]        = "server_disconnected"
        result["error_detail"] = "Server closed connection unexpectedly"
    except aiohttp.TooManyRedirects:
        result["error"]        = "redirect_loop"
        result["error_detail"] = "Too many redirects"
    except Exception as e:
        result["error"]        = "unknown"
        result["error_detail"] = type(e).__name__
    return result


async def fetch_api(session, url, platform):
    hdrs = {**get_headers(), "Accept": "application/json"}
    try:
        async with session.get(
            url, headers=hdrs,
            timeout=aiohttp.ClientTimeout(total=10), ssl=False
        ) as r:
            if r.status == 200:
                raw = await r.json(content_type=None)
                return _parse_api(platform, raw)
    except Exception:
        pass
    return {}


def _parse_api(platform, raw):
    if platform == "GitHub":
        keys = ["name","bio","location","company","blog",
                "public_repos","public_gists","followers",
                "following","created_at","avatar_url","email","twitter_username"]
        return {k: raw[k] for k in keys if raw.get(k) not in (None, "", 0)}

    if platform == "Chess.com":
        keys = ["username","name","title","status","country",
                "location","joined","last_online","followers"]
        return {k: raw[k] for k in keys if raw.get(k) not in (None, "")}

    if platform == "Dailymotion":
        keys = ["screenname","description","city","country",
                "videocount","fans","following"]
        return {k: raw[k] for k in keys if raw.get(k) not in (None, "")}

    if platform == "GitLab":
        if isinstance(raw, list) and raw:
            u = raw[0]
            keys = ["name","username","bio","location","website_url","created_at"]
            return {k: u[k] for k in keys if u.get(k) not in (None, "")}

    if platform == "Bitbucket":
        keys = ["display_name","nickname","website","location","created_on"]
        return {k: raw[k] for k in keys if raw.get(k) not in (None, "")}

    if platform == "Vimeo":
        keys = ["author_name","author_url"]
        return {k: raw[k] for k in keys if raw.get(k) not in (None, "")}

    return {}


# ══════════════════════════════════════════════════════════════════════
# Chunked executor
# ══════════════════════════════════════════════════════════════════════
async def run_scan(username: str):
    items = list(PLATFORMS.items())

    # Build connector with per-host limits (polite)
    connector = aiohttp.TCPConnector(
        limit=30, limit_per_host=3,
        ttl_dns_cache=300, ssl=False
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        all_results = []
        for i in range(0, len(items), CHUNK_SIZE):
            chunk = items[i : i + CHUNK_SIZE]
            tasks = [check_platform(session, n, c, username) for n, c in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    all_results.append(r)
            if i + CHUNK_SIZE < len(items):
                await asyncio.sleep(random.uniform(*CHUNK_DELAY))

    found     = [p for p in all_results if p["found"]]
    not_found = [p for p in all_results if not p["found"] and not p["error"]]
    errors    = [p for p in all_results if p["error"]]

    # Cross-platform data linkage
    linked = {}
    for p in found:
        d = p.get("data", {})
        for key in ["email","twitter_username","blog","location","name",
                    "bio","website_url","country","city","company"]:
            if d.get(key):
                linked.setdefault(key, [])
                linked[key].append({"source": p["platform"], "value": str(d[key])})

    # Confidence summary
    conf = {"high": 0, "medium": 0, "low": 0}
    for p in found:
        conf[p.get("confidence","medium")] = conf.get(p.get("confidence","medium"),0) + 1

    # Error breakdown
    err_types = {}
    for p in errors:
        t = p.get("error","unknown")
        err_types[t] = err_types.get(t,0) + 1

    return {
        "query": {
            "username":          username,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "platforms_checked": len(all_results),
        },
        "summary": {
            "found_count":        len(found),
            "not_found_count":    len(not_found),
            "error_count":        len(errors),
            "score":              round(len(found) / max(len(all_results), 1) * 100, 1),
            "confidence_breakdown": conf,
            "error_types":        err_types,
        },
        "username_analysis":   analyse_username(username),
        "platforms_found":     found,
        "platforms_not_found": not_found,
        "platforms_error":     errors,
        "linked_data":         linked,
        "dork_urls":           build_dorks(username),
    }


# ══════════════════════════════════════════════════════════════════════
# Username analysis
# ══════════════════════════════════════════════════════════════════════
def analyse_username(u: str):
    a = {
        "length":               len(u),
        "has_numbers":          bool(re.search(r"\d", u)),
        "has_underscores":      "_" in u,
        "has_dots":             "." in u,
        "has_hyphens":          "-" in u,
        "all_lowercase":        u.islower(),
        "all_uppercase":        u.isupper(),
        "mixed_case":           not u.islower() and not u.isupper() and u.isalpha(),
        "possible_birth_year":  None,
        "suffix_digits":        None,
        "possible_real_name":   False,
        "common_pattern":       None,
    }
    y = re.findall(r"(19[6-9]\d|20[0-2]\d)", u)
    if y:
        a["possible_birth_year"] = y[0]
    s = re.findall(r"(\d{2,4})$", u)
    if s:
        a["suffix_digits"] = s[0]
    if re.match(r"^[A-Za-z]+[._]?[A-Za-z]+$", u) and not any(c.isdigit() for c in u):
        a["possible_real_name"] = True
    # Pattern detection
    if re.match(r"^[a-z]+\d{4}$", u):
        a["common_pattern"] = "word+year"
    elif re.match(r"^[a-z]+_[a-z]+$", u):
        a["common_pattern"] = "word_word"
    elif re.match(r"^[a-z]+\.[a-z]+$", u):
        a["common_pattern"] = "first.last"
    elif re.match(r"^[A-Z][a-z]+[A-Z][a-z]+$", u):
        a["common_pattern"] = "CamelCase"
    return a


# ══════════════════════════════════════════════════════════════════════
# Dork builder
# ══════════════════════════════════════════════════════════════════════
def build_dorks(username: str):
    out = []
    for d in DORK_TEMPLATES:
        q = d["query"].replace("{username}", username)
        out.append({
            "group":  d["group"],
            "label":  d["label"],
            "desc":   d["desc"],
            "icon":   d["icon"],
            "query":  q,
            "google": f"https://www.google.com/search?q={quote_plus(q)}",
            "bing":   f"https://www.bing.com/search?q={quote_plus(q)}",
            "ddg":    f"https://duckduckgo.com/?q={quote_plus(q)}",
        })
    return out


# ══════════════════════════════════════════════════════════════════════
# Flask
# ══════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()

    if not username:
        return jsonify({"error": "Username is required.", "code": "MISSING_USERNAME"}), 400

    if len(username) > 50:
        return jsonify({"error": "Username must be 50 characters or fewer.", "code": "TOO_LONG"}), 400

    if not re.match(r"^[a-zA-Z0-9._\-]{1,50}$", username):
        return jsonify({
            "error": "Username may only contain letters, numbers, dots ( . ), hyphens ( - ), or underscores ( _ ).",
            "code": "INVALID_CHARS"
        }), 400

    try:
        result = asyncio.run(run_scan(username))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "Scan failed on the server. Please try again.", "code": "SERVER_ERROR", "detail": str(e)}), 500


@app.route("/api/platforms", methods=["GET"])
def list_platforms():
    return jsonify([
        {
            "name":       n,
            "url_template": v["url"],
            "category":   v["category"],
            "icon":       v["icon"],
            "confidence": v["confidence"],
        }
        for n, v in PLATFORMS.items()
    ])


@app.route("/api/dorks", methods=["POST"])
def dork_only():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Username required.", "code": "MISSING_USERNAME"}), 400
    return jsonify(build_dorks(username))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "platforms": len(PLATFORMS), "dorks": len(DORK_TEMPLATES)})


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
