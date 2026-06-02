import argparse
from scanner.headers import check_headers

def main():
    parser = argparse.ArgumentParser(description="Sentinel - Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    args = parser.parse_args()

    print(f"\n[*] Scanning {args.url}...\n")
    
    print("=== Security Headers ===")
    header_results = check_headers(args.url)
    for result in header_results:
        status = "✓ PASS" if result["present"] else "✗ MISSING"
        print(f"{status} | {result['header']}")
        if not result["present"]:
            print(f"   └─ Risk: {result['description']}\n")

if __name__ == "__main__":
    main()