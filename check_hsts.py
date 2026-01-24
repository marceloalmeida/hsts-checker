#!/usr/bin/env python3
"""
HSTS Header Checker
Reads a list of addresses from a file and checks their HSTS headers.
"""

import sys
import csv
import requests
from urllib.parse import urlparse
from typing import Optional, Dict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


def parse_hsts_header(hsts_value: str) -> Dict[str, any]:
    """Parse HSTS header value and extract directives."""
    directives = {}
    parts = [p.strip() for p in hsts_value.split(";")]

    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            directives[key.strip().lower()] = value.strip()
        else:
            # Boolean directives like includeSubDomains, preload
            directives[part.strip().lower()] = True

    return directives


def classify_hsts(hsts_value: Optional[str]) -> tuple[str, str]:
    """
    Classify HSTS configuration and return (emoji, classification).

    Classifications:
    🔒✅ Excellent: max-age >= 31536000 (1 year) with includeSubDomains and preload
    ✅🛡️  Strong: max-age >= 31536000 with includeSubDomains
    ✅     Good: max-age >= 31536000
    ⚠️     Weak: max-age < 31536000
    ❌     Missing: No HSTS header
    """
    if not hsts_value:
        return "❌", "Missing"

    directives = parse_hsts_header(hsts_value)

    # Extract max-age
    max_age = int(directives.get("max-age", 0))
    has_subdomains = "includesubdomains" in directives
    has_preload = "preload" in directives

    # Classify based on configuration
    if max_age >= 31536000:  # 1 year or more
        if has_preload and has_subdomains:
            return "🔒✅", "Excellent"
        elif has_subdomains:
            return "✅🛡️ ", "Strong"
        else:
            return "✅    ", "Good"
    elif max_age > 0:
        return "⚠️    ", "Weak"
    else:
        return "❌    ", "Invalid"


def classify_cache_control(cache_control_value: Optional[str]) -> tuple[str, str]:
    """
    Classify Cache-Control configuration and return (emoji, classification).

    Classifications:
    ✅ Good: no-store or (no-cache and must-revalidate)
    ⚠️ Moderate: has cache control but allows caching
    ❌ Missing: No Cache-Control header
    """
    if not cache_control_value:
        return "❌", "Missing"

    value_lower = cache_control_value.lower()

    # Best practice: no-store prevents any caching
    if "no-store" in value_lower:
        return "✅", "Good (no-store)"

    # Good: no-cache with must-revalidate forces revalidation
    if "no-cache" in value_lower and "must-revalidate" in value_lower:
        return "✅", "Good (revalidate)"

    # Moderate: has cache control but allows caching
    if any(directive in value_lower for directive in ["max-age", "public", "private", "no-cache"]):
        return "⚠️", "Moderate (cacheable)"

    return "❓", "Unknown"


def check_hsts(url: str) -> tuple[str, Optional[str], str, Optional[str], Optional[str], str]:
    """
    Check HSTS header for a given URL.
    Returns (emoji, hsts_value, classification, server_header, cache_control_value, cache_control_classification).
    """
    # Ensure URL has a scheme
    if not urlparse(url).scheme:
        url = f"https://{url}"

    try:
        # Set curl user agent
        headers = {
            'User-Agent': 'curl/8.7.1'
        }

        # Make request (follow redirects, timeout after 5 seconds)
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True, verify=True)

        # Get headers (case-insensitive)
        hsts_value = response.headers.get("Strict-Transport-Security")
        server_header = response.headers.get("Server")
        cache_control_value = response.headers.get("Cache-Control")

        # If still no Server header, try HTTP request to get it
        if not server_header:
            try:
                http_url = url.replace("https://", "http://", 1)
                http_response = requests.get(http_url, headers=headers, timeout=5, allow_redirects=True, verify=False)
                server_header = http_response.headers.get("Server")

                # Also check HTTP redirect history
                if not server_header and http_response.history:
                    for hist_response in http_response.history:
                        server_header = hist_response.headers.get("Server")
                        if server_header:
                            break
            except Exception:
                # If HTTP request fails, continue without Server header
                pass

        emoji, classification = classify_hsts(hsts_value)
        _, cache_classification = classify_cache_control(cache_control_value)

        return emoji, hsts_value, classification, server_header, cache_control_value, cache_classification

    except requests.exceptions.SSLError:
        return "🔓    ", None, "SSL Error", None, None, "N/A"
    except requests.exceptions.ConnectionError:
        return "🔌    ", None, "Connection Error", None, None, "N/A"
    except requests.exceptions.Timeout:
        return "⏱️    ", None, "Timeout", None, None, "N/A"
    except Exception as e:
        return "❓    ", None, f"Error: {str(e)}", None, None, "N/A"


def main():
    """Main function to process addresses from file."""
    if len(sys.argv) != 2:
        print("Usage: python check_hsts.py <addresses_file>")
        print("\nExample addresses_file content:")
        print("  example.com")
        print("  https://another-domain.com")
        print("  subdomain.example.org")
        sys.exit(1)

    addresses_file = sys.argv[1]

    try:
        with open(addresses_file, "r") as f:
            addresses = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        print(f"❌ Error: File '{addresses_file}' not found!")
        sys.exit(1)

    if not addresses:
        print("⚠️  No addresses found in file!")
        sys.exit(1)

    print(f"🔍 Checking HSTS headers for {len(addresses)} address(es)...\n")
    print("=" * 80)

    # Prepare CSV output
    csv_filename = f"hsts_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    csv_rows = []

    # Number of parallel workers (adjust based on your needs)
    max_workers = min(10, len(addresses))

    # Check all addresses in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_address = {
            executor.submit(check_hsts, address): address for address in addresses
        }

        with tqdm(total=len(addresses), desc="Checking HSTS", unit="site") as pbar:
            for future in as_completed(future_to_address):
                address = future_to_address[future]
                try:
                    emoji, hsts_value, classification, server_header, cache_control_value, cache_classification = future.result()
                    results[address] = (
                        emoji,
                        hsts_value,
                        classification,
                        server_header,
                        cache_control_value,
                        cache_classification,
                    )
                except Exception as e:
                    results[address] = ("❓    ", None, f"Error: {str(e)}", None, None, "N/A")
                pbar.update(1)

    # Process results in original order
    for address in addresses:
        emoji, hsts_value, classification, server_header, cache_control_value, cache_classification = results[address]

        print(f"\n{emoji} {address}")
        print(f"   Classification: {classification}")
        if server_header:
            print(f"   Server: {server_header}")
        if cache_control_value:
            print(f"   Cache-Control: {cache_control_value}")
            print(f"   Cache Classification: {cache_classification}")

        if hsts_value:
            print(f"   HSTS Header: {hsts_value}")

            # Parse and display details
            directives = parse_hsts_header(hsts_value)
            max_age_value = ""
            max_age_days = ""
            include_subdomains = "No"
            preload = "No"

            if "max-age" in directives:
                max_age = int(directives["max-age"])
                days = max_age // 86400
                max_age_value = str(max_age)
                max_age_days = str(days)
                print(f"   Max-Age: {max_age} seconds ({days} days)")
            if "includesubdomains" in directives:
                include_subdomains = "Yes"
                print(f"   🛡️  includeSubDomains: enabled")
            if "preload" in directives:
                preload = "Yes"
                print(f"   🔒 preload: enabled")

            # Add to CSV data
            csv_rows.append(
                {
                    "Address": address,
                    "Classification": classification,
                    "Server": server_header or "",
                    "Cache-Control": cache_control_value or "",
                    "Cache Classification": cache_classification,
                    "HSTS Header": hsts_value or "",
                    "Max-Age (seconds)": max_age_value,
                    "Max-Age (days)": max_age_days,
                    "includeSubDomains": include_subdomains,
                    "preload": preload,
                }
            )
        else:
            # No HSTS header or error
            csv_rows.append(
                {
                    "Address": address,
                    "Classification": classification,
                    "Server": server_header or "",
                    "Cache-Control": cache_control_value or "",
                    "Cache Classification": cache_classification,
                    "HSTS Header": "",
                    "Max-Age (seconds)": "",
                    "Max-Age (days)": "",
                    "includeSubDomains": "",
                    "preload": "",
                }
            )

        print("-" * 80)

    # Write CSV file
    try:
        with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "Address",
                "Classification",
                "Server",
                "Cache-Control",
                "Cache Classification",
                "HSTS Header",
                "Max-Age (seconds)",
                "Max-Age (days)",
                "includeSubDomains",
                "preload",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"\n📊 Results exported to: {csv_filename}")
    except Exception as e:
        print(f"\n⚠️  Failed to write CSV file: {e}")

    print("\n✨ Legend:")
    print("  HSTS:")
    print("    🔒✅ Excellent - max-age ≥ 1 year + includeSubDomains + preload")
    print("    ✅🛡️  Strong    - max-age ≥ 1 year + includeSubDomains")
    print("    ✅    Good     - max-age ≥ 1 year")
    print("    ⚠️    Weak     - max-age < 1 year")
    print("    ❌    Missing  - No HSTS header")
    print("  Cache-Control:")
    print("    ✅ Good      - no-store or (no-cache + must-revalidate)")
    print("    ⚠️ Moderate  - has cache control but allows caching")
    print("    ❌ Missing   - No Cache-Control header")
    print("  Errors:")
    print("    🔓    SSL Error")
    print("    🔌    Connection Error")
    print("    ⏱️    Timeout")


if __name__ == "__main__":
    main()
