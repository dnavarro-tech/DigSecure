import argparse
from scanner.headers import check_headers
from scanner.cookies import check_cookies
from scanner.report import generate_report

def main():
    parser = argparse.ArgumentParser(description="DigSecure - Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--output", help="Save report to a markdown file", default=None)
    args = parser.parse_args()

    print(f"\n[*] DigSecure scanning {args.url}...\n")

    print("=== Security Headers ===")
    header_results = check_headers(args.url)
    for result in header_results:
        status = "✓ PASS" if result["present"] else "✗ MISSING"
        print(f"{status} | {result['header']}")
        if not result["present"]:
            print(f"   └─ Risk: {result['description']}\n")

    print("\n=== Cookie Security Audit ===")
    cookie_results = check_cookies(args.url)
    if cookie_results:
        for result in cookie_results:
            status = "✓ PASS" if result["present"] else "✗ MISSING"
            print(f"{status} | {result['cookie_name']} → {result['flag']}")
            if not result["present"]:
                print(f"   └─ Risk: {result['description']}\n")
    else:
        print("   No cookies detected to audit.")

    if args.output:
        report = generate_report(args.url, header_results, cookie_results)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[✓] Report saved to {args.output}")

if __name__ == "__main__":
    main()