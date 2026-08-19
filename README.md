# dns-report

Daily automated report of a client's DNS activity from PiHole v6, sent to Slack.

Run one instance per device you want to report on, each with its own `CLIENT_IP` and `DEVICE_NAME`.

## Setup

### Environment Variables

| Variable | Description |
|---|---|
| `PIHOLE_URL` | PiHole address (no trailing slash) |
| `PIHOLE_PASSWORD` | PiHole application password |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `CLIENT_IP` | Static IP of the device to report on |
| `DEVICE_NAME` | Optional. Label used in the Slack report title (default: `Chromebook`) |

Copy `.env.example` to `.env` and fill in your values for local development.

### Slack Webhook

Create a Slack app with an incoming webhook and activate it for the target channel. Copy the webhook URL to your `SLACK_WEBHOOK_URL` environment variable.

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
