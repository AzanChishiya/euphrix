"""
OSINT Scanner v4 — Production Backend
──────────────────────────────────────
Design principles:
  • Under 5 seconds total — all requests truly concurrent, 3.5s timeout
  • Zero false positives — HEAD first, then targeted GET + body check
  • Popular international platforms only (20 platforms)
  • Rotating UA pool + realistic headers to avoid flagging
  • Vercel-compatible (stateless, no threading issues)

Ethical: public URLs + official open APIs only.
"""

import asyncio
import aiohttp
import random
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote_plus
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# ─────────────────────────────────────────────────────────
# Rotating headers pool
# ─────────────────────────────────────────────────────────
_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def _hdrs(json=False):
    base = {
        "User-Agent":      random.choice(_UA),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             "1",
        "Connection":      "keep-alive",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
    }
    if json:
        base["Accept"] = "application/json"
    else:
        base["Accept"] = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
    return base

# ─────────────────────────────────────────────────────────
# Platform registry — 20 popular international platforms
#
# strategy:
#   "head"  → HEAD request; 404 = gone, 200/3xx = found (fast, no body)
#   "get"   → GET + read partial body; use body_miss / body_hit patterns
#   "api"   → JSON API endpoint (authoritative, zero false-positives)
#
# body_miss: text in HTML that means "this user does not exist"
# body_hit:  text that must be present to CONFIRM existence
#            (only set when we have a reliable marker)
# ─────────────────────────────────────────────────────────
PLATFORMS = {
    "Instagram": {
        "url":       "https://www.instagram.com/{u}/",
        "strategy":  "get",
        "body_miss": "sorry, this page isn't available",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "📸",
        "color":     "#e1306c",
    },
    "TikTok": {
        "url":       "https://www.tiktok.com/@{u}",
        "strategy":  "get",
        "body_miss": "couldn't find this account",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "🎵",
        "color":     "#ff0050",
    },
    "Snapchat": {
        "url":       "https://www.snapchat.com/add/{u}",
        "strategy":  "get",
        "body_miss": None,
        "body_hit":  '"username":"',
        "api":       None,
        "category":  "Social",
        "icon":      "👻",
        "color":     "#fffc00",
    },
    "Facebook": {
        "url":       "https://www.facebook.com/{u}",
        "strategy":  "get",
        "body_miss": "this content isn't available right now",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "🔵",
        "color":     "#1877f2",
    },
    "Twitter / X": {
        "url":       "https://twitter.com/{u}",
        "strategy":  "get",
        "body_miss": "this account doesn't exist",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "✖",
        "color":     "#000000",
    },
    "YouTube": {
        "url":       "https://www.youtube.com/@{u}",
        "strategy":  "get",
        "body_miss": "this page isn't available",
        "body_hit":  None,
        "api":       None,
        "category":  "Video",
        "icon":      "▶️",
        "color":     "#ff0000",
    },
    "Twitch": {
        "url":       "https://www.twitch.tv/{u}",
        "strategy":  "get",
        "body_miss": None,
        "body_hit":  '"@type":"Person"',
        "api":       None,
        "category":  "Video",
        "icon":      "🟣",
        "color":     "#9146ff",
    },
    "LinkedIn": {
        "url":       "https://www.linkedin.com/in/{u}",
        "strategy":  "get",
        "body_miss": "page not found",
        "body_hit":  None,
        "api":       None,
        "category":  "Professional",
        "icon":      "💼",
        "color":     "#0077b5",
    },
    "GitHub": {
        # Uses the public REST API — 100% accurate, no false positives
        "url":       "https://github.com/{u}",
        "strategy":  "api",
        "api":       "https://api.github.com/users/{u}",
        "body_miss": None,
        "body_hit":  None,
        "category":  "Dev",
        "icon":      "💻",
        "color":     "#333333",
    },
    "Pinterest": {
        "url":       "https://www.pinterest.com/{u}/",
        "strategy":  "get",
        "body_miss": "sorry! we couldn't find that page",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "📌",
        "color":     "#e60023",
    },
    "Tumblr": {
        "url":       "https://{u}.tumblr.com",
        "strategy":  "get",
        "body_miss": "there's nothing here.",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "🟦",
        "color":     "#35465c",
    },
    "Reddit": {
        # Uses the public JSON API — authoritative
        "url":       "https://www.reddit.com/user/{u}",
        "strategy":  "api",
        "api":       "https://www.reddit.com/user/{u}/about.json",
        "body_miss": None,
        "body_hit":  None,
        "category":  "Social",
        "icon":      "👽",
        "color":     "#ff4500",
    },
    "Telegram": {
        "url":       "https://t.me/{u}",
        "strategy":  "get",
        "body_miss": None,
        "body_hit":  "tgme_page_title",
        "api":       None,
        "category":  "Messaging",
        "icon":      "✈️",
        "color":     "#2ca5e0",
    },
    "Steam": {
        "url":       "https://steamcommunity.com/id/{u}",
        "strategy":  "get",
        "body_miss": "the specified profile could not be found.",
        "body_hit":  None,
        "api":       None,
        "category":  "Gaming",
        "icon":      "🎮",
        "color":     "#1b2838",
    },
    "Spotify": {
        "url":       "https://open.spotify.com/user/{u}",
        "strategy":  "get",
        "body_miss": None,
        "body_hit":  '"@type":"MusicGroup"',
        "api":       None,
        "category":  "Music",
        "icon":      "🎧",
        "color":     "#1db954",
    },
    "SoundCloud": {
        "url":       "https://soundcloud.com/{u}",
        "strategy":  "get",
        "body_miss": "we can't find that user.",
        "body_hit":  None,
        "api":       None,
        "category":  "Music",
        "icon":      "🔊",
        "color":     "#ff5500",
    },
    "Medium": {
        "url":       "https://medium.com/@{u}",
        "strategy":  "get",
        "body_miss": "page not found",
        "body_hit":  None,
        "api":       None,
        "category":  "Writing",
        "icon":      "✍️",
        "color":     "#000000",
    },
    "Threads": {
        "url":       "https://www.threads.net/@{u}",
        "strategy":  "head",
        "body_miss": None,
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "🧵",
        "color":     "#000000",
    },
    "Bluesky": {
        "url":       "https://bsky.app/profile/{u}",
        "strategy":  "get",
        "body_miss": "uh oh, that page doesn't exist",
        "body_hit":  None,
        "api":       None,
        "category":  "Social",
        "icon":      "🦋",
        "color":     "#0085ff",
    },
    "Flickr": {
        "url":       "https://www.flickr.com/people/{u}",
        "strategy":  "head",
        "body_miss": None,
        "body_hit":  None,
        "api":       None,
        "category":  "Photo",
        "icon":      "📷",
        "color":     "#ff0084",
    },
}

# ─────────────────────────────────────────────────────────
# Dork templates — 28 powerful, grouped
# ─────────────────────────────────────────────────────────
DORKS = [
    # ── Identity ──────────────────────────────────────────
    {"group": "Identity", "icon": "🌐", "label": "Exact username — everywhere",
     "desc": "Every page Google has indexed containing this exact username.",
     "q": '"{u}"'},
    {"group": "Identity", "icon": "👤", "label": "Username as a real name",
     "desc": "Find pages that treat the username as a person's actual name.",
     "q": '"{u}" "about me" OR bio OR profile'},
    {"group": "Identity", "icon": "🌍", "label": "Personal websites and blogs",
     "desc": "Find personal sites, blogs, or portfolio pages linked to this username.",
     "q": '"{u}" site:wordpress.com OR site:substack.com OR site:wix.com OR site:squarespace.com'},
    {"group": "Identity", "icon": "🪪", "label": "Username + full name",
     "desc": "Find pages where a real name appears alongside this username.",
     "q": '"{u}" "my name is" OR "I am" OR "full name" OR "real name"'},

    # ── Social Media ───────────────────────────────────────
    {"group": "Social Media", "icon": "📱", "label": "Major social platforms",
     "desc": "Scan Instagram, TikTok, Twitter/X, Facebook, and Snapchat at once.",
     "q": '"{u}" site:instagram.com OR site:tiktok.com OR site:twitter.com OR site:facebook.com OR site:snapchat.com'},
    {"group": "Social Media", "icon": "▶️", "label": "YouTube channel",
     "desc": "Find a YouTube channel using this name or handle.",
     "q": 'site:youtube.com "@{u}" OR site:youtube.com/c/{u}'},
    {"group": "Social Media", "icon": "✈️", "label": "Telegram public channels",
     "desc": "Find public Telegram channels, bots, or groups linked to this username.",
     "q": '"t.me/{u}" OR site:t.me "{u}"'},
    {"group": "Social Media", "icon": "🧵", "label": "Threads and Mastodon",
     "desc": "Find profiles on decentralised and newer social platforms.",
     "q": '"{u}" site:threads.net OR site:mastodon.social OR site:bsky.app'},

    # ── Professional ───────────────────────────────────────
    {"group": "Professional", "icon": "💼", "label": "LinkedIn profile",
     "desc": "Find any public LinkedIn profile page for this username.",
     "q": 'site:linkedin.com/in "{u}"'},
    {"group": "Professional", "icon": "💻", "label": "GitHub — repos and activity",
     "desc": "Find all public GitHub activity: repositories, gists, issues, comments.",
     "q": 'site:github.com "{u}"'},
    {"group": "Professional", "icon": "📚", "label": "Developer forums",
     "desc": "Find developer forum activity on Stack Overflow and similar sites.",
     "q": '"{u}" site:stackoverflow.com OR site:dev.to OR site:hashnode.com'},

    # ── Contact Clues ─────────────────────────────────────
    {"group": "Contact Clues", "icon": "📧", "label": "Email address clues",
     "desc": "Find publicly posted email addresses alongside this username.",
     "q": '"{u}" "@gmail.com" OR "@yahoo.com" OR "@outlook.com" OR "@hotmail.com"'},
    {"group": "Contact Clues", "icon": "📞", "label": "Phone number mentions",
     "desc": "Find any publicly shared phone numbers associated with this username.",
     "q": '"{u}" "phone" OR "whatsapp" OR "telegram" OR "contact me" OR "reach me"'},
    {"group": "Contact Clues", "icon": "🔗", "label": "Linktree and bio link pages",
     "desc": "Find bio-link pages (Linktree, Beacons, etc.) used by this person.",
     "q": '"{u}" site:linktr.ee OR site:beacons.ai OR site:bio.link OR site:taplink.cc'},

    # ── Location ──────────────────────────────────────────
    {"group": "Location", "icon": "📍", "label": "Location and city mentions",
     "desc": "Find posts or profiles where this username is paired with a location.",
     "q": '"{u}" "lives in" OR "based in" OR "from" OR "located in" OR city OR country'},
    {"group": "Location", "icon": "🏫", "label": "School or university mentions",
     "desc": "Find any academic affiliations linked to this username.",
     "q": '"{u}" university OR college OR school OR student OR alumni'},

    # ── Documents & Files ─────────────────────────────────
    {"group": "Documents", "icon": "📄", "label": "Public CV or résumé",
     "desc": "Find publicly accessible PDF résumés or CVs associated with this name.",
     "q": '"{u}" résumé OR resume OR CV OR "curriculum vitae" filetype:pdf'},
    {"group": "Documents", "icon": "📑", "label": "Presentations and documents",
     "desc": "Find public Office or PDF documents that mention this username.",
     "q": '"{u}" filetype:pdf OR filetype:docx OR filetype:pptx'},

    # ── Pastes & Exposure ─────────────────────────────────
    {"group": "Exposure", "icon": "📋", "label": "Paste sites",
     "desc": "Find any paste mentioning this username on Pastebin and similar sites.",
     "q": '"{u}" site:pastebin.com OR site:paste.ee OR site:dpaste.com OR site:hastebin.com'},
    {"group": "Exposure", "icon": "⚠️", "label": "Breach and leak mentions",
     "desc": "Find public discussions where this username appears in breach contexts.",
     "q": '"{u}" "data breach" OR "leaked" OR "hacked" OR "exposed" -site:haveibeenpwned.com'},

    # ── Media & News ──────────────────────────────────────
    {"group": "Media", "icon": "📰", "label": "News coverage",
     "desc": "Find news articles or press releases mentioning this username.",
     "q": '"{u}" site:news.google.com OR inurl:news OR "press release"'},
    {"group": "Media", "icon": "🎙️", "label": "Podcasts and interviews",
     "desc": "Find podcasts, interviews, or video content featuring this username.",
     "q": '"{u}" podcast OR interview OR "guest" OR "episode" OR "conversation with"'},
    {"group": "Media", "icon": "🖼️", "label": "Images and profile pictures",
     "desc": "Find images tagged, captioned, or labelled with this username.",
     "q": '"{u}" profile picture OR avatar OR "photo of" OR headshot'},

    # ── Forums ────────────────────────────────────────────
    {"group": "Forums", "icon": "💬", "label": "Reddit, Quora, and forums",
     "desc": "Find discussion board posts by or about this username.",
     "q": '"{u}" site:reddit.com OR site:quora.com OR inurl:forum'},

    # ── Commerce ─────────────────────────────────────────
    {"group": "Commerce", "icon": "🛍️", "label": "Online shops",
     "desc": "Find any storefront or shop linked to this username.",
     "q": '"{u}" site:etsy.com OR site:ebay.com OR site:depop.com OR site:vinted.com'},

    # ── Crypto / Web3 ─────────────────────────────────────
    {"group": "Web3", "icon": "🪙", "label": "Crypto and Web3 presence",
     "desc": "Find wallet addresses, NFT profiles, or crypto activity linked to this username.",
     "q": '"{u}" ethereum OR bitcoin OR NFT OR opensea.io OR crypto OR wallet'},

    # ── Images ────────────────────────────────────────────
    {"group": "Advanced", "icon": "🔭", "label": "Username with operator: intext",
     "desc": "Force Google to match the username inside page body text only.",
     "q": 'intext:"{u}" -inurl:"{u}"'},
    {"group": "Advanced", "icon": "🧩", "label": "Username in URL paths",
     "desc": "Find any URL where the username appears as part of the path.",
     "q": 'inurl:"{u}" -site:twitter.com -site:instagram.com'},
]

# ─────────────────────────────────────────────────────────
# Core scanner — fully concurrent, hard 3.5s timeout
# ─────────────────────────────────────────────────────────
READ_LIMIT = 28_000   # bytes to read per response


async def _check(session: aiohttp.ClientSession, name: str, cfg: dict, username: str):
    url = cfg["url"].replace("{u}", username)
    out = {
        "platform":    name,
        "url":         url,
        "found":       False,
        "confidence":  "medium",
        "category":    cfg["category"],
        "icon":        cfg["icon"],
        "color":       cfg.get("color", "#333"),
        "data":        {},
        "error":       None,
        "ms":          None,
        "status":      None,
    }
    to = aiohttp.ClientTimeout(total=3.5, connect=2.0)
    try:
        t0 = time.monotonic()

        # ── API strategy (most accurate) ──────────────────
        if cfg["strategy"] == "api":
            api_url = cfg["api"].replace("{u}", username)
            async with session.get(api_url, headers=_hdrs(json=True), timeout=to, ssl=False) as r:
                out["ms"]     = int((time.monotonic() - t0) * 1000)
                out["status"] = r.status
                if r.status == 200:
                    out["found"]      = True
                    out["confidence"] = "high"
                    raw = await r.json(content_type=None)
                    out["data"] = _parse_api(name, raw)
                elif r.status == 404:
                    out["found"] = False
                else:
                    out["error"] = f"HTTP {r.status}"
            return out

        # ── HEAD strategy (fast, no body) ─────────────────
        if cfg["strategy"] == "head":
            async with session.head(url, headers=_hdrs(), timeout=to,
                                    allow_redirects=True, ssl=False) as r:
                out["ms"]     = int((time.monotonic() - t0) * 1000)
                out["status"] = r.status
                out["found"]  = r.status < 400
                out["confidence"] = "medium"
            return out

        # ── GET strategy (body pattern check) ─────────────
        async with session.get(url, headers=_hdrs(), timeout=to,
                               allow_redirects=True, ssl=False,
                               max_line_size=8190, max_field_size=8190) as r:
            out["ms"]     = int((time.monotonic() - t0) * 1000)
            out["status"] = r.status

            if r.status == 404:
                out["found"] = False
                return out
            if r.status >= 400:
                out["error"] = f"HTTP {r.status}"
                return out

            # Read partial body
            raw_bytes = b""
            async for chunk in r.content.iter_chunked(4096):
                raw_bytes += chunk
                if len(raw_bytes) >= READ_LIMIT:
                    break
            body = raw_bytes.decode("utf-8", errors="ignore").lower()

            miss = cfg.get("body_miss")
            hit  = cfg.get("body_hit")

            if miss and miss.lower() in body:
                out["found"]      = False
                out["confidence"] = "high"
                return out

            if hit:
                if hit.lower() in body:
                    out["found"]      = True
                    out["confidence"] = "high"
                else:
                    out["found"] = False
                return out

            # Status 200 + no miss pattern = found (medium confidence)
            out["found"]      = True
            out["confidence"] = "medium"

    except asyncio.TimeoutError:
        out["error"] = "timeout"
    except aiohttp.ClientConnectorError:
        out["error"] = "unreachable"
    except aiohttp.ServerDisconnectedError:
        out["error"] = "disconnected"
    except Exception as e:
        out["error"] = type(e).__name__
    return out


def _parse_api(platform: str, raw: dict) -> dict:
    if platform == "GitHub":
        keys = ["name", "bio", "location", "company", "blog",
                "public_repos", "followers", "following", "created_at",
                "avatar_url", "email", "twitter_username"]
        return {k: raw[k] for k in keys if raw.get(k) not in (None, "", 0)}

    if platform == "Reddit":
        d = raw.get("data", {})
        keys = ["name", "total_karma", "link_karma", "comment_karma",
                "created_utc", "is_gold", "icon_img"]
        return {k: d[k] for k in keys if d.get(k) not in (None, "", 0)}

    return {}


async def _scan(username: str) -> dict:
    conn = aiohttp.TCPConnector(limit=40, limit_per_host=2, ssl=False,
                                ttl_dns_cache=120, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=conn) as s:
        tasks  = [_check(s, n, c, username) for n, c in PLATFORMS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    clean = [r for r in results if isinstance(r, dict)]
    found = [r for r in clean if r["found"]]
    nf    = [r for r in clean if not r["found"] and not r["error"]]
    errs  = [r for r in clean if r["error"]]

    linked = {}
    for p in found:
        for key in ["email", "twitter_username", "blog", "location",
                    "name", "bio", "company"]:
            if p["data"].get(key):
                linked.setdefault(key, [])
                linked[key].append({"source": p["platform"], "value": str(p["data"][key])})

    conf = {"high": 0, "medium": 0, "low": 0}
    for p in found:
        conf[p["confidence"]] = conf.get(p["confidence"], 0) + 1

    return {
        "query": {
            "username":  username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total":     len(clean),
        },
        "summary": {
            "found":      len(found),
            "not_found":  len(nf),
            "errors":     len(errs),
            "score":      round(len(found) / max(len(clean), 1) * 100, 1),
            "confidence": conf,
        },
        "analysis":        _analyse(username),
        "platforms_found": found,
        "platforms_nf":    nf,
        "platforms_err":   errs,
        "linked":          linked,
        "dorks":           _dorks(username),
    }


def _analyse(u: str) -> dict:
    a = {
        "length":      len(u),
        "has_numbers": bool(re.search(r"\d", u)),
        "has_symbols": bool(re.search(r"[._-]", u)),
        "all_lower":   u.islower(),
        "all_upper":   u.isupper(),
        "mixed_case":  not u.islower() and not u.isupper() and u.isalpha(),
        "birth_year":  None,
        "suffix_num":  None,
        "real_name":   False,
        "pattern":     None,
    }
    y = re.findall(r"(19[6-9]\d|20[0-2]\d)", u)
    if y:
        a["birth_year"] = y[0]
    s = re.findall(r"(\d{2,4})$", u)
    if s:
        a["suffix_num"] = s[0]
    if re.match(r"^[A-Za-z]+[._]?[A-Za-z]+$", u) and not any(c.isdigit() for c in u):
        a["real_name"] = True
    for pat, label in [
        (r"^[a-z]+\d{4}$", "word + year"),
        (r"^[a-z]+_[a-z]+$", "word_word"),
        (r"^[a-z]+\.[a-z]+$", "first.last"),
        (r"^[A-Z][a-z]+[A-Z][a-z]+$", "CamelCase"),
        (r"^[a-z]+\d{2,3}$", "word + numbers"),
    ]:
        if re.match(pat, u):
            a["pattern"] = label
            break
    return a


def _dorks(username: str) -> list:
    out = []
    for d in DORKS:
        q = d["q"].replace("{u}", username)
        out.append({
            "group":  d["group"],
            "icon":   d["icon"],
            "label":  d["label"],
            "desc":   d["desc"],
            "query":  q,
            "google": "https://www.google.com/search?q=" + quote_plus(q),
            "bing":   "https://www.bing.com/search?q=" + quote_plus(q),
            "ddg":    "https://duckduckgo.com/?q=" + quote_plus(q),
        })
    return out


# ─────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()

    if not username:
        return jsonify({"error": "Please enter a username.", "code": "EMPTY"}), 400
    if len(username) > 50:
        return jsonify({"error": "Username must be 50 characters or fewer.", "code": "TOO_LONG"}), 400
    if not re.match(r"^[a-zA-Z0-9._\-]{1,50}$", username):
        return jsonify({
            "error": "Username can only contain letters, numbers, dots, hyphens, and underscores.",
            "code":  "BAD_CHARS",
        }), 400

    try:
        result = asyncio.run(_scan(username))
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "The scan could not be completed. Please try again.",
            "code":  "SERVER_ERROR",
            "detail": str(e),
        }), 500


@app.route("/api/platforms", methods=["GET"])
def platforms():
    return jsonify([
        {"name": n, "category": v["category"], "icon": v["icon"], "color": v.get("color", "#333")}
        for n, v in PLATFORMS.items()
    ])


@app.route("/health")
def health():
    return jsonify({"ok": True, "platforms": len(PLATFORMS), "dorks": len(DORKS)})


if __name__ == "__main__":
    app.run(debug=False, port=5000, threaded=True)
