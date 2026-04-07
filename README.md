# OSINT Scanner — Deep Username Intelligence Tool

Ethical OSINT tool that checks publicly accessible profile URLs and
official public APIs across 25+ platforms. No auth bypass, no private data.

## Quick Start

### 1. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the server

```bash
python app.py
```

### 3. Open your browser

```
http://localhost:5000
```

---

## Features

- **Username scan** across 25+ platforms (Dev, Social, Gaming, Creative, Professional)
- **Public API enrichment** — GitHub, Reddit, HackerNews, Dev.to, Keybase
- **Gravatar lookup** — if an email is provided
- **Cross-platform data mapping** — finds shared bios, locations, linked accounts
- **Username pattern analysis** — detects embedded years, suffixes, character patterns
- **JSON export** — full structured report downloadable or copy-to-clipboard
- **Beautiful dark UI** — category filters, grid/list view, expandable data cards

## Platforms Checked

| Category       | Platforms |
|----------------|-----------|
| Dev / Code     | GitHub, GitLab, Bitbucket, NPM, PyPI, HackerNews, Dev.to |
| Social         | Reddit, Twitter/X, Instagram, TikTok, Pinterest, Tumblr, Mastodon |
| Gaming         | Steam, Twitch, Roblox |
| Creative       | Medium, Behance, Dribbble, Flickr, SoundCloud |
| Professional   | LinkedIn, AngelList |
| Security       | Keybase |

## Ethics & Legal

- Only queries **public** URLs (no login required to view them normally)
- Uses only **official public APIs** (no scraping private data)
- Follows **robots.txt** spirit — checks existence via HTTP status codes
- No credential harvesting, no session hijacking, no ToS violations
- Results reflect what any person can find manually through a browser

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Serves the frontend |
| POST | `/api/scan` | `{ username, email? }` → full scan result |
| GET | `/api/platforms` | List all platforms being checked |

## JSON Output Structure

```json
{
  "query": { "username": "...", "timestamp": "..." },
  "summary": { "found_count": 5, "score": 20.0, ... },
  "username_analysis": { "length": 8, "has_numbers": true, ... },
  "platforms_found": [ { "platform": "GitHub", "url": "...", "data": {...} } ],
  "platforms_not_found": [...],
  "linked_data": { "location": [{ "source": "GitHub", "value": "London" }] },
  "gravatar": { "found": true, "display_name": "...", ... }
}
```
