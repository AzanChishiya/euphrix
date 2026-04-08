# OSINT Scanner v2 — Public Intelligence Tool

Ethical, body-pattern-verified username scanner across 35+ popular platforms.

## Quick Start

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Open → http://localhost:5000

---

## What's New in v2

| Feature | v1 | v2 |
|---|---|---|
| Platform count | 25 | 35+ |
| Scan method | HTTP status only | HTTP status + body-pattern matching |
| Confidence levels | No | High / Medium / Low per result |
| Google Dork generator | No | 12 pre-built dork links (Google + Bing) |
| Ethics modal | No | Full modal with agreement required |
| Instagram/TikTok/Snapchat/Facebook | Partial | ✅ All included |
| API enrichment | GitHub, Reddit | GitHub, GitLab, Chess.com, Dailymotion |
| Cross-platform data map | Basic | Full (location, name, bio, links) |

---

## Platforms Covered

| Category | Platforms |
|---|---|
| Social | Instagram, TikTok, Snapchat, Facebook, Twitter/X, Threads, Pinterest, Tumblr, Mastodon |
| Video | YouTube, Twitch, Vimeo, Dailymotion |
| Dev | GitHub, GitLab, Stack Overflow, NPM, PyPI, Replit, Codepen |
| Music | Spotify, SoundCloud, Last.fm |
| Gaming | Steam, Roblox, Chess.com |
| Creative | Medium, Behance, Dribbble, DeviantArt, Flickr, Wattpad, Patreon |
| Messaging | Telegram, Discord (public) |
| Professional | LinkedIn |
| Forums | Quora |
| Shopping | Etsy |

---

## How Scanning Works

1. **HTTP check** — request the public profile URL
2. **Status code filter** — 404/4xx = not found
3. **Body-pattern check** — look for platform-specific "not found" text OR required presence text inside the page body
4. **Confidence rating** assigned:
   - **HIGH** — body pattern confirmed presence or absence
   - **MEDIUM** — HTTP status only (no false-positive text found)
   - **LOW** — redirect-based detection

This eliminates most false positives from platforms that return 200 for missing profiles.

---

## Google Dork Generator

Generates 12 pre-built search query URLs using Google/Bing operators:
- Exact username across all sites
- Username on specific social platforms
- Username + email clues (from public posts)
- Username + location mentions
- Username in news, forums, pastes
- Resume/CV/portfolio filetype searches

**No automated scraping** — clicking opens a normal browser search tab. You review results manually.

---

## API Endpoints

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/` | — | Frontend HTML |
| POST | `/api/scan` | `{ username }` | Full scan JSON |
| GET | `/api/platforms` | — | Platform list |
| POST | `/api/dorks` | `{ username }` | Dork URL list |

---

## Ethics

- Only checks **public URLs** — no login required to view them normally
- Only uses **official public APIs** — no reverse engineering
- **No email scraping**, no phone harvesting, no auth-system abuse
- Dork generator produces **clickable links**, does not auto-query Google
- Users must agree to an ethics statement before using the tool
