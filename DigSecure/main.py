import argparse
from scanner.headers import check_headers
from scanner.cookies import check_cookies

def main():
    parser = argparse.ArgumentParser(description="DigSecure - Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
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

if __name__ == "__main__":
    main()