#!/usr/bin/env python3
"""Daily DNS activity report for a Chromebook from PiHole v6, sent to Slack."""

import argparse
import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests
import tldextract

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


def rollup_domain(domain):
    """Roll up a full domain to its registered domain (e.g. s.youtube.com → youtube.com).

    Falls back to the original domain string if tldextract can't determine a
    registered domain (e.g. bare hostnames, .local, in-addr.arpa).
    """
    extracted = tldextract.extract(domain)
    return extracted.top_domain_under_public_suffix or domain


def load_categories(path="domain_categories.json"):
    """Load domain→category mapping from JSON file."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning("%s not found, all domains will show as Unknown", path)
        return {}
    except json.JSONDecodeError as e:
        log.warning("Failed to parse %s: %s", path, e)
        return {}


def get_category(domain, categories):
    """Return the human-readable category for a domain, or 'Unknown'."""
    return categories.get(domain, "Unknown")


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

        # should_ignore runs on the full original domain
        if should_ignore(domain, ignore_set):
            continue

        # Roll up to registered domain before counting
        rolled = rollup_domain(domain)
        domain_counts[rolled] += 1
        if blocked:
            blocked_domains[rolled] += 1

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


def _build_domain_table(domain_counts, categories):
    """Build a monospace table of domains, categories, and query counts."""
    rows = domain_counts.most_common()
    if not rows:
        return "  _None_"

    # Compute column widths
    dom_width = max(len("Domain"), max(len(d) for d, _ in rows))
    cat_width = max(len("Category"), max(len(get_category(d, categories)) for d, _ in rows))
    cnt_width = max(len("Queries"), len(str(rows[0][1])))

    header = f"{'Domain':<{dom_width}}  {'Category':<{cat_width}}  {'Queries':>{cnt_width}}"
    separator = "─" * (dom_width + 2 + cat_width + 2 + cnt_width)

    lines = [header, separator]
    for domain, count in rows:
        cat = get_category(domain, categories)
        lines.append(f"{domain:<{dom_width}}  {cat:<{cat_width}}  {count:>{cnt_width}}")

    return "```\n" + "\n".join(lines) + "\n```"


def build_slack_message(stats, report_date, categories):
    """Build the main Slack message blocks."""
    top_visited = stats["domain_counts"].most_common(5)
    top_blocked = stats["blocked_domains"].most_common(5)

    top_visited_lines = []
    for d, c in top_visited:
        cat = get_category(d, categories)
        top_visited_lines.append(f"  {d} ({cat}) — {c}")
    top_visited_text = "\n".join(top_visited_lines) or "  _None_"

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


def build_thread_reply(stats, categories):
    """Build the thread reply with a complete domain table."""
    table = _build_domain_table(stats["domain_counts"], categories)
    lines = ["*All Non-Ignored Domains:*\n", table]

    if stats["blocked_domains"]:
        blocked_rows = stats["blocked_domains"].most_common()
        dom_width = max(len("Domain"), max(len(d) for d, _ in blocked_rows))
        cnt_width = max(len("Queries"), len(str(blocked_rows[0][1])))
        header = f"{'Domain':<{dom_width}}  {'Queries':>{cnt_width}}"
        separator = "─" * (dom_width + 2 + cnt_width)
        blocked_lines = [header, separator]
        for domain, count in blocked_rows:
            blocked_lines.append(f"{domain:<{dom_width}}  {count:>{cnt_width}}")
        blocked_table = "```\n" + "\n".join(blocked_lines) + "\n```"
        lines.append("\n*All Blocked Domains:*\n")
        lines.append(blocked_table)

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

    categories = load_categories()
    log.info("Loaded %d domain category entries", len(categories))

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
    blocks = build_slack_message(stats, report_date, categories)
    thread_text = build_thread_reply(stats, categories)

    send_to_slack(config, blocks, thread_text, debug=args.debug)

    log.info("Done — report sent to Slack")


if __name__ == "__main__":
    main()
