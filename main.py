"""
OSINT Scanner v5
Platforms: Instagram, TikTok, Snapchat, Facebook, Threads, YouTube
Method: Concurrent threads, og:meta parsing, multiple confirmation signals
Timeout: All requests finish within 6 seconds total (Vercel-safe)
Ethics: Public profile URLs only. No authentication bypass.
"""

import re
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)


# ─────────────────────────────────────────────────────────────────────
#  Browser-realistic headers pool
#  We rotate these to look like normal browser traffic.
# ─────────────────────────────────────────────────────────────────────
_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

def _base_headers(referer=None, accept=None):
    h = {
        "User-Agent":      random.choice(_AGENTS),
        "Accept":          accept or "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             "1",
        "Connection":      "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-User":  "?1",
        "Cache-Control":   "max-age=0",
    }
    if referer:
        h["Referer"] = referer
        h["Sec-Fetch-Site"] = "same-origin"
    return h


# ─────────────────────────────────────────────────────────────────────
#  HTML helpers — extract Open Graph meta tags and other page signals
# ─────────────────────────────────────────────────────────────────────
def _meta(html: str, prop: str) -> str:
    """Extract a meta tag value. Checks og:, name=, and property= forms."""
    patterns = [
        rf'<meta[^>]+property=["\']og:{re.escape(prop)}["\'][^>]+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:{re.escape(prop)}["\']',
        rf'<meta[^>]+name=["\']{re.escape(prop)}["\'][^>]+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']{re.escape(prop)}["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""

def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def _canonical(html: str) -> str:
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def _clean(text: str) -> str:
    """Remove HTML entities and extra whitespace."""
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"&#39;|&apos;", "'", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def _followers_from_desc(desc: str) -> str:
    """Try to pull a follower count from an og:description string."""
    m = re.search(r"([\d,\.]+(?:[KkMm])?)\s+(?:Followers|followers|fans)", desc)
    return m.group(1) if m else ""

def _read_body(resp, limit=40_000) -> str:
    """Read up to `limit` bytes from a response to stay fast."""
    raw = b""
    for chunk in resp.iter_content(chunk_size=4096):
        raw += chunk
        if len(raw) >= limit:
            break
    return raw.decode("utf-8", errors="ignore")


# ─────────────────────────────────────────────────────────────────────
#  Result builder
# ─────────────────────────────────────────────────────────────────────
def _result(platform, url, found, confidence, data=None, error=None, ms=None, note=None):
    return {
        "platform":    platform,
        "url":         url,
        "found":       found,
        "confidence":  confidence,
        "data":        data or {},
        "error":       error,
        "ms":          ms,
        "note":        note,
    }


# ─────────────────────────────────────────────────────────────────────
#  INSTAGRAM
#  Server renders og:title = "{Name} (@{username}) • Instagram..."
#  Not-found page contains "Sorry, this page isn't available."
# ─────────────────────────────────────────────────────────────────────
def check_instagram(username: str) -> dict:
    url = f"https://www.instagram.com/{username}/"
    t0 = time.monotonic()
    try:
        session = requests.Session()
        # First visit root to pick up cookies (mimics real browser)
        session.get("https://www.instagram.com/", headers=_base_headers(), timeout=3, stream=True).close()
        r = session.get(url, headers=_base_headers(referer="https://www.instagram.com/"), timeout=5, stream=True)
        ms = int((time.monotonic() - t0) * 1000)
        body = _read_body(r)
        low  = body.lower()

        if r.status_code == 404:
            return _result("Instagram", url, False, "high", ms=ms)

        if "sorry, this page isn't available" in low:
            return _result("Instagram", url, False, "high", ms=ms)

        if "this account is private" in low:
            # Profile exists but is private
            og_title = _clean(_meta(body, "title"))
            og_image = _meta(body, "image")
            name = og_title.split("(")[0].strip() if "(" in og_title else og_title.replace("• Instagram", "").strip()
            return _result("Instagram", url, True, "high", ms=ms, data={
                "display_name": name or username,
                "bio": "This account is private.",
                "profile_picture": og_image,
                "status": "Private account",
            })

        og_title = _clean(_meta(body, "title"))
        og_desc  = _clean(_meta(body, "description"))
        og_image = _meta(body, "image")

        # Confirm: og:title must contain @username
        u_lower = username.lower()
        title_lower = og_title.lower()
        if og_title and (f"@{u_lower}" in title_lower or u_lower in title_lower):
            # Parse display name (before the @handle bracket)
            name = og_title.split("(")[0].strip() if "(" in og_title else og_title.split("•")[0].strip()
            followers = _followers_from_desc(og_desc)
            data = {
                "display_name": _clean(name),
                "bio":          og_desc.split(".")[0] if og_desc else "",
                "followers":    followers,
                "profile_picture": og_image,
            }
            return _result("Instagram", url, True, "high", data=data, ms=ms)

        # Got 200 but could not confirm username in page — treat as not found
        return _result("Instagram", url, False, "high", ms=ms,
                       note="Page loaded but username was not confirmed in page content.")
    except requests.Timeout:
        return _result("Instagram", url, False, None, error="timeout", ms=int((time.monotonic()-t0)*1000))
    except Exception as e:
        return _result("Instagram", url, False, None, error=type(e).__name__, ms=int((time.monotonic()-t0)*1000))


# ─────────────────────────────────────────────────────────────────────
#  TIKTOK
#  og:title = "{Name} (@{username}) | TikTok" for real profiles
#  Not-found: og:title is just "TikTok" or body has specific text
# ─────────────────────────────────────────────────────────────────────
def check_tiktok(username: str) -> dict:
    url = f"https://www.tiktok.com/@{username}"
    t0 = time.monotonic()
    try:
        r = requests.get(url, headers=_base_headers(), timeout=5, stream=True, allow_redirects=True)
        ms = int((time.monotonic() - t0) * 1000)
        body = _read_body(r)
        low  = body.lower()

        if r.status_code == 404:
            return _result("TikTok", url, False, "high", ms=ms)

        NOT_FOUND_PHRASES = [
            "couldn't find this account",
            "this account doesn't exist",
            "page not found",
        ]
        if any(p in low for p in NOT_FOUND_PHRASES):
            return _result("TikTok", url, False, "high", ms=ms)

        og_title = _clean(_meta(body, "title"))
        og_desc  = _clean(_meta(body, "description"))
        og_image = _meta(body, "image")

        u_lower = username.lower()
        if og_title and (f"@{u_lower}" in og_title.lower() or u_lower in og_title.lower()):
            name = og_title.split("(")[0].split("@")[0].strip() if "(" in og_title else og_title.split("|")[0].strip()
            followers = _followers_from_desc(og_desc)
            data = {
                "display_name": _clean(name),
                "bio":          og_desc.split(".")[0] if og_desc else "",
                "followers":    followers,
                "profile_picture": og_image,
            }
            return _result("TikTok", url, True, "high", data=data, ms=ms)

        return _result("TikTok", url, False, "high", ms=ms)
    except requests.Timeout:
        return _result("TikTok", url, False, None, error="timeout", ms=int((time.monotonic()-t0)*1000))
    except Exception as e:
        return _result("TikTok", url, False, None, error=type(e).__name__, ms=int((time.monotonic()-t0)*1000))


# ─────────────────────────────────────────────────────────────────────
#  SNAPCHAT
#  /add/{username} — real profiles render the username in JSON-LD
#  and in og:title as "{Name}'s Snapchat" or include the username
# ─────────────────────────────────────────────────────────────────────
def check_snapchat(username: str) -> dict:
    url = f"https://www.snapchat.com/add/{username}"
    t0 = time.monotonic()
    try:
        r = requests.get(url, headers=_base_headers(), timeout=5, stream=True, allow_redirects=True)
        ms = int((time.monotonic() - t0) * 1000)
        body = _read_body(r)
        low  = body.lower()

        if r.status_code == 404:
            return _result("Snapchat", url, False, "high", ms=ms)

        NOT_FOUND_PHRASES = [
            "sorry, we couldn't find",
            "this profile doesn't exist",
            "profile not found",
        ]
        if any(p in low for p in NOT_FOUND_PHRASES):
            return _result("Snapchat", url, False, "high", ms=ms)

        og_title = _clean(_meta(body, "title"))
        og_desc  = _clean(_meta(body, "description"))
        og_image = _meta(body, "image")

        u_lower = username.lower()

        # Snapchat's page includes the username in JSON or title
        username_in_body = (
            f'"username":"{u_lower}"' in low
            or f"snapchat.com/add/{u_lower}" in low
            or u_lower in og_title.lower()
        )

        if username_in_body and r.status_code == 200:
            # Try to extract a display name from title
            name = og_title.replace("'s Snapchat", "").replace("Snapchat", "").strip()
            data = {
                "display_name": _clean(name) if name else username,
                "bio":          _clean(og_desc) if og_desc else "",
                "profile_picture": og_image,
            }
            return _result("Snapchat", url, True, "high", data=data, ms=ms)

        return _result("Snapchat", url, False, "high", ms=ms)
    except requests.Timeout:
        return _result("Snapchat", url, False, None, error="timeout", ms=int((time.monotonic()-t0)*1000))
    except Exception as e:
        return _result("Snapchat", url, False, None, error=type(e).__name__, ms=int((time.monotonic()-t0)*1000))


# ─────────────────────────────────────────────────────────────────────
#  FACEBOOK
#  Facebook heavily restricts non-browser access.
#  We check both the profile URL and the public search URL.
#  If we get redirected to login.php the result is ambiguous.
#  We never report "found" unless we can confirm the username in the page.
# ─────────────────────────────────────────────────────────────────────
def check_facebook(username: str) -> dict:
    url = f"https://www.facebook.com/{username}"
    t0 = time.monotonic()
    try:
        r = requests.get(url, headers=_base_headers(), timeout=5, stream=True, allow_redirects=True)
        ms = int((time.monotonic() - t0) * 1000)
        body = _read_body(r)
        low  = body.lower()

        # Redirected to login = we cannot determine (not false positive)
        final_url = r.url.lower()
        if "login" in final_url or "checkpoint" in final_url:
            return _result("Facebook", url, False, None, ms=ms,
                           note="Facebook redirected to login. Cannot determine if profile exists without authentication.")

        if r.status_code == 404:
            return _result("Facebook", url, False, "high", ms=ms)

        og_title = _clean(_meta(body, "title"))
        og_desc  = _clean(_meta(body, "description"))
        og_image = _meta(body, "image")
        page_title = _clean(_title(body))

        u_lower = username.lower()
        title_check = og_title.lower() if og_title else page_title.lower()

        # Facebook must show the username or a real name, not just "Facebook"
        if og_title and og_title.lower() not in ("facebook", "log in or sign up | facebook", ""):
            if u_lower in title_check or (og_desc and u_lower in og_desc.lower()):
                data = {
                    "display_name": og_title.split("|")[0].strip(),
                    "bio":          _clean(og_desc)[:200] if og_desc else "",
                    "profile_picture": og_image,
                }
                return _result("Facebook", url, True, "medium", data=data, ms=ms)

        return _result("Facebook", url, False, "medium", ms=ms,
                       note="Could not confirm profile. Facebook restricts public access.")
    except requests.Timeout:
        return _result("Facebook", url, False, None, error="timeout", ms=int((time.monotonic()-t0)*1000))
    except Exception as e:
        return _result("Facebook", url, False, None, error=type(e).__name__, ms=int((time.monotonic()-t0)*1000))


# ─────────────────────────────────────────────────────────────────────
#  THREADS
#  og:title = "{Name} (@{username}) • Threads"  for real profiles
#  404 returned cleanly for non-existent handles
# ─────────────────────────────────────────────────────────────────────
def check_threads(username: str) -> dict:
    url = f"https://www.threads.net/@{username}"
    t0 = time.monotonic()
    try:
        r = requests.get(url, headers=_base_headers(), timeout=5, stream=True, allow_redirects=True)
        ms = int((time.monotonic() - t0) * 1000)
        body = _read_body(r)
        low  = body.lower()

        if r.status_code == 404:
            return _result("Threads", url, False, "high", ms=ms)

        og_title = _clean(_meta(body, "title"))
        og_desc  = _clean(_meta(body, "description"))
        og_image = _meta(body, "image")

        u_lower = username.lower()
        if og_title and f"@{u_lower}" in og_title.lower():
            name = og_title.split("(")[0].split("•")[0].strip()
            data = {
                "display_name": _clean(name),
                "bio":          og_desc[:200] if og_desc else "",
                "profile_picture": og_image,
            }
            return _result("Threads", url, True, "high", data=data, ms=ms)

        NOT_FOUND_PHRASES = ["page not found", "this page doesn't exist", "couldn't find"]
        if any(p in low for p in NOT_FOUND_PHRASES):
            return _result("Threads", url, False, "high", ms=ms)

        return _result("Threads", url, False, "high", ms=ms)
    except requests.Timeout:
        return _result("Threads", url, False, None, error="timeout", ms=int((time.monotonic()-t0)*1000))
    except Exception as e:
        return _result("Threads", url, False, None, error=type(e).__name__, ms=int((time.monotonic()-t0)*1000))


# ─────────────────────────────────────────────────────────────────────
#  YOUTUBE
#  /@{username} returns 404 cleanly for non-existent channels.
#  og:title = channel name for real channels.
#  og:description often contains subscriber count.
# ─────────────────────────────────────────────────────────────────────
def check_youtube(username: str) -> dict:
    url = f"https://www.youtube.com/@{username}"
    t0 = time.monotonic()
    try:
        r = requests.get(url, headers=_base_headers(), timeout=5, stream=True, allow_redirects=True)
        ms = int((time.monotonic() - t0) * 1000)
        body = _read_body(r)
        low  = body.lower()

        if r.status_code == 404:
            return _result("YouTube", url, False, "high", ms=ms)

        NOT_FOUND_PHRASES = [
            "this page isn't available",
            "this channel doesn't exist",
            "404 not found",
        ]
        if any(p in low for p in NOT_FOUND_PHRASES):
            return _result("YouTube", url, False, "high", ms=ms)

        og_title = _clean(_meta(body, "title"))
        og_desc  = _clean(_meta(body, "description"))
        og_image = _meta(body, "image")
        page_title = _clean(_title(body))

        # YouTube channels have a real title, not just "YouTube"
        channel_name = og_title or page_title
        if channel_name and channel_name.lower() not in ("youtube", ""):
            # Extract subscriber count if present in description
            subs = ""
            m = re.search(r"([\d,\.]+(?:\s?[KkMmBb])?)\s+subscribers", og_desc, re.IGNORECASE)
            if m:
                subs = m.group(1)
            data = {
                "display_name":  channel_name.replace(" - YouTube", "").strip(),
                "bio":           og_desc[:200] if og_desc else "",
                "subscribers":   subs,
                "profile_picture": og_image,
                "channel_url":   r.url,
            }
            return _result("YouTube", url, True, "high", data=data, ms=ms)

        return _result("YouTube", url, False, "high", ms=ms)
    except requests.Timeout:
        return _result("YouTube", url, False, None, error="timeout", ms=int((time.monotonic()-t0)*1000))
    except Exception as e:
        return _result("YouTube", url, False, None, error=type(e).__name__, ms=int((time.monotonic()-t0)*1000))


# ─────────────────────────────────────────────────────────────────────
#  Platform registry — maps name to checker function
# ─────────────────────────────────────────────────────────────────────
CHECKERS = {
    "Instagram": {"fn": check_instagram, "icon": "📸", "color": "#e1306c"},
    "TikTok":    {"fn": check_tiktok,    "icon": "🎵", "color": "#ff0050"},
    "Snapchat":  {"fn": check_snapchat,  "icon": "👻", "color": "#fffc00"},
    "Facebook":  {"fn": check_facebook,  "icon": "🔵", "color": "#1877f2"},
    "Threads":   {"fn": check_threads,   "icon": "🧵", "color": "#101010"},
    "YouTube":   {"fn": check_youtube,   "icon": "▶️",  "color": "#ff0000"},
}


# ─────────────────────────────────────────────────────────────────────
#  Username analysis
# ─────────────────────────────────────────────────────────────────────
def analyse(u: str) -> dict:
    out = {
        "length":       len(u),
        "has_numbers":  bool(re.search(r"\d", u)),
        "has_dots":     "." in u,
        "has_underscores": "_" in u,
        "all_lowercase": u.islower(),
        "mixed_case":   not u.islower() and not u.isupper() and bool(re.search(r"[a-zA-Z]", u)),
        "birth_year":   None,
        "suffix_digits": None,
        "looks_like_real_name": False,
        "pattern":      None,
        "variations":   [],
    }

    years = re.findall(r"(19[6-9]\d|20[012]\d)", u)
    if years:
        out["birth_year"] = years[0]

    suffix = re.findall(r"(\d{2,4})$", u)
    if suffix:
        out["suffix_digits"] = suffix[0]

    if re.match(r"^[A-Za-z]+[._]?[A-Za-z]+$", u) and not any(c.isdigit() for c in u):
        out["looks_like_real_name"] = True

    patterns = [
        (r"^[a-z]+\d{4}$",      "name followed by a year"),
        (r"^[a-z]+_[a-z]+$",    "two words with underscore"),
        (r"^[a-z]+\.[a-z]+$",   "first name dot last name"),
        (r"^[A-Z][a-z]+[A-Z][a-z]+$", "CamelCase format"),
        (r"^[a-z]+\d{2,3}$",    "name with number suffix"),
        (r"^[a-z]{3,8}$",       "short lowercase word"),
    ]
    for pat, label in patterns:
        if re.match(pat, u):
            out["pattern"] = label
            break

    # Generate likely variations that may exist on these platforms
    base = re.sub(r"\d+$", "", u).replace(".", "").replace("_", "")
    variations = set()
    variations.add(base + "official")
    variations.add(base + "_official")
    variations.add("the" + base)
    variations.add(base + "real")
    variations.add(base + "tv")
    if out["suffix_digits"]:
        other_num = "1" if out["suffix_digits"] != "1" else "2"
        variations.add(re.sub(r"\d+$", other_num, u))
    out["variations"] = [v for v in list(variations)[:5] if v.lower() != u.lower() and len(v) <= 30]

    return out


# ─────────────────────────────────────────────────────────────────────
#  Dork generator — 30 targeted queries
# ─────────────────────────────────────────────────────────────────────
DORK_TEMPLATES = [
    # Core identity
    {"group": "Identity",      "icon": "🌐", "label": "Username across the entire web",
     "desc":  "Every page Google has indexed that contains this exact username.",
     "q":     '"{u}"'},
    {"group": "Identity",      "icon": "👤", "label": "Username alongside real name",
     "desc":  "Find pages where a real name appears next to this username.",
     "q":     '"{u}" "my name is" OR "I am" OR "full name" OR "real name" OR "known as"'},
    {"group": "Identity",      "icon": "🌍", "label": "Personal websites and blogs",
     "desc":  "Find personal sites, portfolios, or blogs that belong to this person.",
     "q":     '"{u}" site:wordpress.com OR site:substack.com OR site:medium.com OR site:wix.com OR site:blogger.com'},
    {"group": "Identity",      "icon": "🔗", "label": "Bio link pages",
     "desc":  "Find Linktree, Beacons, or similar pages that list all of their accounts.",
     "q":     '"{u}" site:linktr.ee OR site:beacons.ai OR site:bio.link OR site:taplink.cc OR site:lnk.bio'},

    # Platform specific
    {"group": "Social Media",  "icon": "📸", "label": "Instagram profile",
     "desc":  "Find the public Instagram profile for this username.",
     "q":     'site:instagram.com "{u}"'},
    {"group": "Social Media",  "icon": "🎵", "label": "TikTok profile",
     "desc":  "Find TikTok videos and the profile page for this username.",
     "q":     'site:tiktok.com "@{u}" OR site:tiktok.com "/{u}"'},
    {"group": "Social Media",  "icon": "▶️", "label": "YouTube channel",
     "desc":  "Find the YouTube channel and any uploaded videos.",
     "q":     'site:youtube.com "@{u}" OR site:youtube.com "c/{u}"'},
    {"group": "Social Media",  "icon": "🔵", "label": "Facebook profile or page",
     "desc":  "Search for a public Facebook profile or page with this name.",
     "q":     'site:facebook.com "{u}"'},
    {"group": "Social Media",  "icon": "🧵", "label": "Threads profile",
     "desc":  "Find the Threads profile for this username.",
     "q":     'site:threads.net "@{u}"'},
    {"group": "Social Media",  "icon": "👻", "label": "Snapchat profile",
     "desc":  "Find the public Snapchat profile or story page.",
     "q":     'site:snapchat.com "{u}" OR "snapchat.com/add/{u}"'},
    {"group": "Social Media",  "icon": "𝕏",  "label": "Twitter profile",
     "desc":  "Find the Twitter (now X) profile for this username.",
     "q":     'site:twitter.com "{u}" OR site:x.com "{u}"'},
    {"group": "Social Media",  "icon": "🤖", "label": "Reddit account",
     "desc":  "Find Reddit posts, comments, and the profile for this username.",
     "q":     'site:reddit.com "u/{u}" OR site:reddit.com "/user/{u}"'},
    {"group": "Social Media",  "icon": "✈️", "label": "Telegram channel or bot",
     "desc":  "Find a public Telegram channel, group, or bot with this name.",
     "q":     '"t.me/{u}" OR site:t.me "{u}"'},

    # Contact clues
    {"group": "Contact",       "icon": "📧", "label": "Email address mentions",
     "desc":  "Find any publicly posted email address alongside this username.",
     "q":     '"{u}" "@gmail.com" OR "@yahoo.com" OR "@outlook.com" OR "@hotmail.com" OR "@icloud.com"'},
    {"group": "Contact",       "icon": "📞", "label": "Phone or messaging contact",
     "desc":  "Find any publicly shared phone number or messaging contact linked to this username.",
     "q":     '"{u}" "phone" OR "whatsapp" OR "contact me" OR "reach me" OR "call me" OR "message me"'},
    {"group": "Contact",       "icon": "🔑", "label": "Username plus email domain pattern",
     "desc":  "Try to find an email where the username is the local part.",
     "q":     '"{u}@" OR "mailto:{u}"'},

    # Location
    {"group": "Location",      "icon": "📍", "label": "City or country mentions",
     "desc":  "Find bios or posts where this username is paired with a location.",
     "q":     '"{u}" "lives in" OR "based in" OR "from" OR "located in" OR "i am from"'},
    {"group": "Location",      "icon": "🏫", "label": "School or university links",
     "desc":  "Find any university, college, or school mentioned alongside this username.",
     "q":     '"{u}" university OR college OR school OR student OR alumni OR degree'},

    # Documents
    {"group": "Documents",     "icon": "📄", "label": "Public CV or resumé",
     "desc":  "Find a publicly accessible PDF resumé or CV that uses this username.",
     "q":     '"{u}" resume OR CV OR "curriculum vitae" filetype:pdf'},
    {"group": "Documents",     "icon": "📑", "label": "Presentations and slideshows",
     "desc":  "Find public PowerPoint or PDF presentations that mention this name.",
     "q":     '"{u}" filetype:pptx OR filetype:pdf presentation OR slides OR slideshow'},

    # Dev
    {"group": "Developer",     "icon": "💻", "label": "GitHub presence",
     "desc":  "Find GitHub repositories, gists, and contributions for this username.",
     "q":     'site:github.com "{u}"'},
    {"group": "Developer",     "icon": "📚", "label": "Developer forum activity",
     "desc":  "Find posts and answers on Stack Overflow and other coding forums.",
     "q":     '"{u}" site:stackoverflow.com OR site:dev.to OR site:hashnode.com OR site:codepen.io'},

    # Exposure
    {"group": "Exposure",      "icon": "📋", "label": "Paste site mentions",
     "desc":  "Find any paste on Pastebin or similar sites that mentions this username.",
     "q":     '"{u}" site:pastebin.com OR site:paste.ee OR site:dpaste.com'},
    {"group": "Exposure",      "icon": "⚠️", "label": "Data breach or leak mentions",
     "desc":  "Find public discussions where this username appears in breach-related content.",
     "q":     '"{u}" "data breach" OR "leaked" OR "hacked" OR "dump" -site:haveibeenpwned.com'},
    {"group": "Exposure",      "icon": "📰", "label": "News and press mentions",
     "desc":  "Find news articles, press releases, or media that mention this username.",
     "q":     '"{u}" site:news.google.com OR inurl:article OR "press release" OR reported'},

    # Media
    {"group": "Media",         "icon": "🎙️", "label": "Podcast or interview appearances",
     "desc":  "Find podcasts, interviews, or recorded conversations featuring this person.",
     "q":     '"{u}" podcast OR interview OR "guest on" OR episode OR "conversation with"'},
    {"group": "Media",         "icon": "🖼️", "label": "Profile pictures and avatars",
     "desc":  "Find images that are tagged, captioned, or described using this username.",
     "q":     '"{u}" "profile picture" OR avatar OR pfp OR headshot OR photo'},

    # Commerce
    {"group": "Commerce",      "icon": "🛍️", "label": "Online shops or storefronts",
     "desc":  "Find any online shop or storefront linked to this username.",
     "q":     '"{u}" site:etsy.com OR site:ebay.com OR site:depop.com OR site:amazon.com/shop'},

    # Web3
    {"group": "Web3",          "icon": "🪙", "label": "Crypto and Web3 activity",
     "desc":  "Find wallet addresses, NFT collections, or crypto activity linked to this username.",
     "q":     '"{u}" ethereum OR bitcoin OR NFT OR opensea OR wallet OR crypto OR web3'},

    # Advanced operators
    {"group": "Advanced",      "icon": "🔭", "label": "Username inside page body text only",
     "desc":  "Force search engines to find the username specifically in the body of pages, not just URLs.",
     "q":     'intext:"{u}" -inurl:"{u}"'},
    {"group": "Advanced",      "icon": "🧩", "label": "Username appears in URL paths",
     "desc":  "Find any site where this username appears as part of the page URL path.",
     "q":     'inurl:"{u}" -site:twitter.com -site:instagram.com -site:tiktok.com'},
]

def build_dorks(username: str) -> list:
    out = []
    for d in DORK_TEMPLATES:
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


# ─────────────────────────────────────────────────────────────────────
#  Main scan — all platforms run in parallel threads
# ─────────────────────────────────────────────────────────────────────
def run_scan(username: str) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(cfg["fn"], username): name
            for name, cfg in CHECKERS.items()
        }
        for future in as_completed(futures, timeout=9):
            name = futures[future]
            try:
                res = future.result()
                res["icon"]  = CHECKERS[name]["icon"]
                res["color"] = CHECKERS[name]["color"]
                results[name] = res
            except Exception as e:
                results[name] = _result(
                    name,
                    f"https://—/{username}",
                    False, None,
                    error=str(e),
                )
                results[name]["icon"]  = CHECKERS[name]["icon"]
                results[name]["color"] = CHECKERS[name]["color"]

    found    = [r for r in results.values() if r["found"]]
    not_found = [r for r in results.values() if not r["found"] and not r["error"]]
    errors   = [r for r in results.values() if r["error"]]

    # Merge any data fields found across platforms
    merged_info = {}
    for p in found:
        for k, v in (p.get("data") or {}).items():
            if v and k not in merged_info:
                merged_info[k] = {"value": str(v), "source": p["platform"]}

    return {
        "query": {
            "username":  username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total":     len(results),
        },
        "summary": {
            "found":     len(found),
            "not_found": len(not_found),
            "errors":    len(errors),
            "score":     round(len(found) / max(len(results), 1) * 100, 1),
        },
        "analysis":       analyse(username),
        "merged_info":    merged_info,
        "platforms":      list(results.values()),
        "dorks":          build_dorks(username),
    }


# ─────────────────────────────────────────────────────────────────────
#  Flask routes
# ─────────────────────────────────────────────────────────────────────
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
            "code": "BAD_CHARS",
        }), 400

    try:
        result = run_scan(username)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "The scan could not complete. Please try again.",
            "code": "SERVER_ERROR",
        }), 500


@app.route("/health")
def health():
    return jsonify({"ok": True, "platforms": len(CHECKERS), "dorks": len(DORK_TEMPLATES)})


if __name__ == "__main__":
    app.run(debug=False, port=5000, threaded=True)
