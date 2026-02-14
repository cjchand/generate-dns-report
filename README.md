# dns-report

Daily automated report of Chromebook DNS activity from PiHole v6, sent to Slack.

## Setup

### Environment Variables

| Variable | Description |
|---|---|
| `PIHOLE_URL` | PiHole address (no trailing slash) |
| `PIHOLE_PASSWORD` | PiHole application password |
| `SLACK_BOT_TOKEN` | Slack bot token with `chat:write` scope |
| `SLACK_CHANNEL` | Slack channel ID |
| `CLIENT_IP` | Chromebook's static IP |

Copy `.env.example` to `.env` and fill in your values for local development.

### Slack Bot

Create a Slack app with the `chat:write` bot scope and install it to your workspace. Invite the bot to the target channel.

### Ignore List

Edit `ignore_domains.txt` to customize which domains are excluded from the report. Supports subdomain matching — e.g., `google.com` also matches `maps.google.com`.

## Usage

### Local (debug mode)

```bash
pip install -r requirements.txt
export $(cat .env | xargs)
python dns_report.py --debug
```

### Docker

```bash
docker build -t dns-report .
docker run --env-file .env dns-report --debug   # test
docker run --env-file .env dns-report            # send to Slack
```

### Container Image

The GitHub Actions workflow automatically builds and pushes to `ghcr.io/cjchand/generate-dns-report` on every push to `main`.

```bash
docker pull ghcr.io/cjchand/generate-dns-report:latest
docker run --env-file .env ghcr.io/cjchand/generate-dns-report:latest
```
