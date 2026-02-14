#!/usr/bin/env python3
"""Daily DNS activity report for a Chromebook from PiHole v6, sent to Slack."""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import requests


def get_config():
    """Load configuration from environment variables."""
    required = ["PIHOLE_URL", "PIHOLE_PASSWORD", "SLACK_BOT_TOKEN", "SLACK_CHANNEL", "CLIENT_IP"]
    config = {}
    missing = []
    for key in required:
        val = os.environ.get(key)
        if not val:
            missing.append(key)
        config[key] = val
    if missing:
        print(f"Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
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
        print(f"Warning: {path} not found, no domains will be ignored", file=sys.stderr)
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
    resp = requests.post(url, json={"password": config["PIHOLE_PASSWORD"]}, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    sid = data.get("session", {}).get("sid")
    if not sid:
        print(f"Authentication failed: {json.dumps(data, indent=2)}", file=sys.stderr)
        sys.exit(1)
    return sid


def fetch_queries(config, sid, from_ts, until_ts, debug=False):
    """Fetch all queries for the client IP in the given time range, handling pagination."""
    headers = {"X-FTL-SID": sid}
    all_queries = []
    cursor = None

    while True:
        url = f"{config['PIHOLE_URL']}/api/queries?client={config['CLIENT_IP']}&from={from_ts}&until={until_ts}"
        if cursor:
            url += f"&cursor={cursor}"

        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        queries = data.get("queries", [])
        all_queries.extend(queries)

        if debug and len(all_queries) <= 5:
            print(f"Sample query data: {json.dumps(queries[:3], indent=2)}")

        cursor = data.get("cursor")
        if not cursor or not queries:
            break

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
    hourly = defaultdict(int)

    for q in queries:
        domain = q.get("domain", "unknown").lower().rstrip(".")
        timestamp = q.get("time", 0)
        hour = datetime.fromtimestamp(timestamp, tz=timezone.utc).hour

        hourly[hour] += 1

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
        "hourly": hourly,
    }

    if debug:
        print(f"\nAggregated stats:")
        print(f"  Total queries: {total}")
        print(f"  Blocked: {blocked_count}")
        print(f"  Unique non-ignored domains: {unique_domains}")
        print(f"  Top 10 domains: {domain_counts.most_common(10)}")
        print(f"  Top 5 blocked: {blocked_domains.most_common(5)}")

    return stats


def build_hourly_chart(hourly):
    """Build a text-based hourly activity bar chart."""
    if not hourly:
        return "_No hourly data available_"

    max_count = max(hourly.values()) if hourly else 1
    lines = []
    for hour in range(24):
        count = hourly.get(hour, 0)
        bar_len = round((count / max_count) * 20) if max_count > 0 else 0
        bar = "\u2588" * bar_len
        lines.append(f"`{hour:02d}:00` {bar} {count}")
    return "\n".join(lines)


def build_slack_message(stats, report_date):
    """Build the main Slack message blocks."""
    top_visited = stats["domain_counts"].most_common(5)
    top_blocked = stats["blocked_domains"].most_common(5)

    top_visited_text = "\n".join(f"  {d} — {c}" for d, c in top_visited) or "  _None_"
    top_blocked_text = "\n".join(f"  {d} — {c}" for d, c in top_blocked) or "  _None_"
    hourly_chart = build_hourly_chart(stats["hourly"])

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Chromebook DNS Report — {report_date}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Total Queries:* {stats['total']}\n"
                    f"*Blocked:* {stats['blocked']}\n"
                    f"*Unique Domains (non-ignored):* {stats['unique']}"
                ),
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top 5 Visited (non-ignored):*\n{top_visited_text}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top 5 Blocked:*\n{top_blocked_text}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Hourly Activity:*\n{hourly_chart}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                }
            ],
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
    """Send the report to Slack: main message + thread reply."""
    headers = {
        "Authorization": f"Bearer {config['SLACK_BOT_TOKEN']}",
        "Content-Type": "application/json",
    }

    # Main message
    payload = {
        "channel": config["SLACK_CHANNEL"],
        "blocks": blocks,
        "text": "Chromebook DNS Report",  # fallback
    }

    if debug:
        print(f"\nSlack main payload:\n{json.dumps(payload, indent=2)}")
        print(f"\nThread reply text length: {len(thread_text)} chars")
        print("(Skipping send in debug mode)")
        return

    resp = requests.post("https://slack.com/api/chat.postMessage", headers=headers, json=payload, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("ok"):
        print(f"Slack API error: {data.get('error')}", file=sys.stderr)
        sys.exit(1)

    thread_ts = data["ts"]

    # Thread reply — split into chunks if needed (Slack limit ~4000 chars)
    max_len = 3900
    chunks = []
    current = ""
    for line in thread_text.split("\n"):
        if len(current) + len(line) + 1 > max_len:
            chunks.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)

    for chunk in chunks:
        reply_payload = {
            "channel": config["SLACK_CHANNEL"],
            "thread_ts": thread_ts,
            "text": chunk,
        }
        resp = requests.post("https://slack.com/api/chat.postMessage", headers=headers, json=reply_payload, timeout=10)
        resp.raise_for_status()
        reply_data = resp.json()
        if not reply_data.get("ok"):
            print(f"Slack thread reply error: {reply_data.get('error')}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Generate DNS activity report from PiHole v6")
    parser.add_argument("--debug", action="store_true", help="Print debug info and skip sending to Slack")
    args = parser.parse_args()

    config = get_config()
    ignore_set = load_ignore_domains()

    # Yesterday's full day in UTC
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    start_of_day = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = yesterday.replace(hour=23, minute=59, second=59, microsecond=0)
    from_ts = int(start_of_day.timestamp())
    until_ts = int(end_of_day.timestamp())
    report_date = yesterday.strftime("%Y-%m-%d")

    print(f"Fetching queries for {config['CLIENT_IP']} from {report_date}...")

    sid = authenticate(config)
    queries = fetch_queries(config, sid, from_ts, until_ts, debug=args.debug)

    print(f"Retrieved {len(queries)} queries")

    stats = aggregate(queries, ignore_set, debug=args.debug)
    blocks = build_slack_message(stats, report_date)
    thread_text = build_thread_reply(stats)

    send_to_slack(config, blocks, thread_text, debug=args.debug)

    if not args.debug:
        print("Report sent to Slack successfully!")


if __name__ == "__main__":
    main()
