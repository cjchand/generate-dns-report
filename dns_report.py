#!/usr/bin/env python3
"""Daily DNS activity report for a Chromebook from PiHole v6, sent to Slack."""

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def get_config():
    """Load configuration from environment variables."""
    required = ["PIHOLE_URL", "PIHOLE_PASSWORD", "SLACK_WEBHOOK_URL", "CLIENT_IP"]
    config = {}
    missing = []
    for key in required:
        val = os.environ.get(key)
        if not val:
            missing.append(key)
        config[key] = val
    if missing:
        log.error("Missing required environment variables: %s", ", ".join(missing))
        sys.exit(1)
    # Strip trailing slash from URL
    config["PIHOLE_URL"] = config["PIHOLE_URL"].rstrip("/")
    return config


def load_ignore_domains(path="ignore_domains.txt"):
    """Load domains to ignore from file. Returns a set of lowercase domains."""
    domains = set()
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    except FileNotFoundError:
        log.warning("%s not found, no domains will be ignored", path)
    return domains


def should_ignore(domain, ignore_set):
    """Check if domain or any parent domain is in the ignore set (subdomain-aware)."""
    domain = domain.lower().rstrip(".")
    if domain in ignore_set:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in ignore_set:
            return True
    return False


def authenticate(config):
    """Authenticate with PiHole v6 API and return session ID."""
    url = f"{config['PIHOLE_URL']}/api/auth"
    log.info("Authenticating with PiHole at %s", config["PIHOLE_URL"])
    resp = requests.post(url, json={"password": config["PIHOLE_PASSWORD"]}, timeout=10)
    if resp.status_code == 401:
        log.error("Authentication failed (401): %s", resp.text)
    resp.raise_for_status()
    data = resp.json()
    sid = data.get("session", {}).get("sid")
    if not sid:
        log.error("Authentication failed: %s", json.dumps(data, indent=2))
        sys.exit(1)
    log.info("Authenticated successfully")
    return sid


def fetch_queries(config, sid, from_ts, until_ts, debug=False):
    """Fetch all queries for the client IP in the given time range, handling pagination."""
    headers = {"X-FTL-SID": sid}
    all_queries = []
    cursor = None
    page_size = 200
    start = 0

    page = 0
    while True:
        page += 1
        url = (
            f"{config['PIHOLE_URL']}/api/queries"
            f"?client_ip={config['CLIENT_IP']}"
            f"&from={from_ts}&until={until_ts}"
            f"&start={start}&length={page_size}"
        )
        if cursor:
            url += f"&cursor={cursor}"

        log.info("Fetching queries page %d (start=%d, collected %d so far)", page, start, len(all_queries))
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        queries = data.get("queries", [])
        all_queries.extend(queries)

        if debug and len(all_queries) <= 5:
            log.debug("Sample query data: %s", json.dumps(queries[:3], indent=2))

        # Capture cursor on first request to freeze the result set
        if cursor is None:
            cursor = data.get("cursor")

        if len(queries) < page_size:
            break

        start += page_size

    log.info("Fetched %d total queries across %d page(s)", len(all_queries), page)
    return all_queries


def is_blocked(query):
    """Determine if a query was blocked based on its status field."""
    status = str(query.get("status", "")).upper()
    return any(keyword in status for keyword in ["BLOCK", "GRAVITY", "DENY"])


def aggregate(queries, ignore_set, debug=False):
    """Aggregate query data into report statistics."""
    total = len(queries)
    blocked_count = 0
    domain_counts = Counter()
    blocked_domains = Counter()

    for q in queries:
        domain = q.get("domain", "unknown").lower().rstrip(".")

        blocked = is_blocked(q)
        if blocked:
            blocked_count += 1
            blocked_domains[domain] += 1

        if not should_ignore(domain, ignore_set):
            domain_counts[domain] += 1

    unique_domains = len(domain_counts)

    stats = {
        "total": total,
        "blocked": blocked_count,
        "unique": unique_domains,
        "domain_counts": domain_counts,
        "blocked_domains": blocked_domains,
    }

    log.info("Aggregated: %d total, %d blocked, %d unique non-ignored domains",
             total, blocked_count, unique_domains)

    if debug:
        log.debug("Top 10 domains: %s", domain_counts.most_common(10))
        log.debug("Top 5 blocked: %s", blocked_domains.most_common(5))

    return stats


def build_slack_message(stats, report_date):
    """Build the main Slack message blocks."""
    top_visited = stats["domain_counts"].most_common(5)
    top_blocked = stats["blocked_domains"].most_common(5)

    top_visited_text = "\n".join(f"  {d} — {c}" for d, c in top_visited) or "  _None_"
    top_blocked_text = "\n".join(f"  {d} — {c}" for d, c in top_blocked) or "  _None_"

    pct_blocked = (
        f"{stats['blocked'] / stats['total']:.0%}" if stats["total"] else "0%"
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Chromebook DNS — {report_date}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{stats['total']}* queries · "
                    f"*{stats['blocked']}* blocked ({pct_blocked}) · "
                    f"*{stats['unique']}* unique"
                ),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top Visited:*\n{top_visited_text}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top Blocked:*\n{top_blocked_text}",
            },
        },
    ]
    return blocks


def build_thread_reply(stats):
    """Build the thread reply with complete domain lists."""
    lines = ["*All Non-Ignored Domains:*\n"]
    for domain, count in sorted(stats["domain_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"  {domain} — {count}")

    if stats["blocked_domains"]:
        lines.append("\n*All Blocked Domains:*\n")
        for domain, count in sorted(stats["blocked_domains"].items(), key=lambda x: -x[1]):
            lines.append(f"  {domain} — {count}")

    return "\n".join(lines)


def send_to_slack(config, blocks, thread_text, debug=False):
    """Send the report to Slack via incoming webhook."""
    # Append domain details as additional blocks
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": thread_text[:3000],
        },
    })
    # If thread text was truncated, add continuation blocks
    remaining = thread_text[3000:]
    while remaining:
        chunk = remaining[:3000]
        remaining = remaining[3000:]
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": chunk,
            },
        })

    payload = {
        "blocks": blocks,
        "text": "Chromebook DNS Report",  # fallback
    }

    if debug:
        log.debug("Slack webhook payload:\n%s", json.dumps(payload, indent=2))
        log.info("Debug mode — skipping Slack send")
        return

    log.info("Sending report to Slack (%d blocks)", len(blocks))
    resp = requests.post(config["SLACK_WEBHOOK_URL"], json=payload, timeout=10)
    resp.raise_for_status()
    if resp.text != "ok":
        log.error("Slack webhook error: %s", resp.text)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate DNS activity report from PiHole v6")
    parser.add_argument("--debug", action="store_true", help="Print debug info and skip sending to Slack")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger(__name__).setLevel(logging.DEBUG)

    config = get_config()
    log.info("Loaded configuration for client %s against %s", config["CLIENT_IP"], config["PIHOLE_URL"])

    ignore_set = load_ignore_domains()
    log.info("Loaded %d ignore domain patterns", len(ignore_set))

    # Yesterday's full day in UTC
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    start_of_day = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = yesterday.replace(hour=23, minute=59, second=59, microsecond=0)
    from_ts = int(start_of_day.timestamp())
    until_ts = int(end_of_day.timestamp())
    report_date = yesterday.strftime("%Y-%m-%d")

    log.info("Report date: %s (timestamps %d–%d)", report_date, from_ts, until_ts)

    sid = authenticate(config)
    queries = fetch_queries(config, sid, from_ts, until_ts, debug=args.debug)

    stats = aggregate(queries, ignore_set, debug=args.debug)

    log.info("Building Slack message")
    blocks = build_slack_message(stats, report_date)
    thread_text = build_thread_reply(stats)

    send_to_slack(config, blocks, thread_text, debug=args.debug)

    log.info("Done — report sent to Slack")


if __name__ == "__main__":
    main()
