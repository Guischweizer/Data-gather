#!/usr/bin/env python3
import argparse
import asyncio
from utils import email_lookup, name_lookup
from utils.ai_analyzer import AIAnalyzer

async def main():
    parser = argparse.ArgumentParser(description="Simple OSINT Tool")
    parser.add_argument("--email", help="Target email address")
    parser.add_argument("--name", help="Target full name")
    parser.add_argument("--test", action="store_true", help="Run in test mode without API calls")
    args = parser.parse_args()

    findings = {}
    analyzer = AIAnalyzer(test_mode=args.test)

    if args.email:
        print(f"[*] Looking up email: {args.email}")
        findings['email'] = email_lookup.search_by_email(args.email)
    if args.name:
        print(f"[*] Looking up name: {args.name}")
        findings['name'] = name_lookup.search_by_name(args.name)

    if findings:
        print("\n[*] AI Analysis of findings:")
        analysis = await analyzer.analyze_findings(findings)
        print(analysis)

if __name__ == "__main__":
    asyncio.run(main())

