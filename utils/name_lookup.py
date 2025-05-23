from duckduckgo_search import DDGS

def search_by_name(name):
    print("[*] Searching DuckDuckGo...")
    with DDGS() as ddgs:
        results = ddgs.text(name, max_results=5)
        if results:
            for r in results:
                print(f"[+] {r['title']} - {r['url']}")
        else:
            print("[-] No results found.")

