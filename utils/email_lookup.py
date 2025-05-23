import requests
import json
import time
import re
import base64
import hashlib
from urllib.parse import urlencode, quote
from duckduckgo_search import DDGS
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import os

console = Console()

class EmailOSINT:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def gravatar_lookup(self, email):
        """Check if email has an associated Gravatar profile"""
        console.print("[bold blue]🔍 Checking Gravatar...[/bold blue]")

        try:
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

            response = self.session.get(gravatar_url, timeout=10)
            if response.status_code == 200:
                profile_url = f"https://www.gravatar.com/{email_hash}"
                console.print(f"[green]✓ Gravatar found:[/green] {profile_url}")

                try:
                    profile_response = self.session.get(f"{profile_url}.json", timeout=10)
                    if profile_response.status_code == 200:
                        profile_data = profile_response.json()
                        if 'entry' in profile_data and profile_data['entry']:
                            entry = profile_data['entry'][0]
                            console.print(f"[cyan]   Name:[/cyan] {entry.get('displayName', 'N/A')}")
                            console.print(f"[cyan]   About:[/cyan] {entry.get('aboutMe', 'N/A')}")
                            if 'urls' in entry:
                                for url in entry['urls']:
                                    console.print(f"[cyan]   URL:[/cyan] {url.get('value', 'N/A')}")
                except:
                    pass
            else:
                console.print("[yellow]⚠ No Gravatar found[/yellow]")

        except Exception as e:
            console.print(f"[red]✗ Gravatar lookup failed: {str(e)}[/red]")

    def check_haveibeenpwned(self, email):
        """Check Have I Been Pwned for breaches"""
        console.print("[bold blue]🔍 Checking Have I Been Pwned...[/bold blue]")

        try:
            breach_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
            response = self.session.get(breach_url, timeout=10)

            if response.status_code == 200:
                breaches = response.json()
                console.print(f"[red]⚠ Found in {len(breaches)} breach(es):[/red]")

                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Breach Name", style="red")
                table.add_column("Date", style="yellow")
                table.add_column("Compromised Data", style="cyan")

                for breach in breaches:
                    compromised_data = ", ".join(breach.get('DataClasses', []))
                    table.add_row(
                        breach['Name'],
                        breach['BreachDate'],
                        compromised_data
                    )
                console.print(table)

            elif response.status_code == 404:
                console.print("[green]✓ No breaches found in HIBP[/green]")
            else:
                console.print(f"[yellow]⚠ HIBP check failed (Status: {response.status_code})[/yellow]")

        except Exception as e:
            console.print(f"[red]✗ HIBP lookup failed: {str(e)}[/red]")

    def check_dehashed(self, email, api_key=None):
        """Check DeHashed for leaked credentials"""
        if not api_key:
            console.print("[yellow]⚠ DeHashed API key not provided, skipping...[/yellow]")
            return

        console.print("[bold blue]🔍 Checking DeHashed...[/bold blue]")

        try:
            url = "https://api.dehashed.com/search"
            params = {'query': f'email:{email}', 'size': 100}

            response = self.session.get(url, params=params,
                                        auth=(api_key.split(':')[0], api_key.split(':')[1]),
                                        timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get('entries'):
                    console.print(f"[red]⚠ Found {len(data['entries'])} entries in DeHashed[/red]")

                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Database", style="red")
                    table.add_column("Username", style="yellow")
                    table.add_column("Password", style="cyan")
                    table.add_column("Hash", style="green")

                    for entry in data['entries'][:10]:
                        table.add_row(
                            entry.get('database_name', 'N/A'),
                            entry.get('username', 'N/A'),
                            entry.get('password', 'N/A')[:20] + "..." if entry.get('password') and len(entry.get('password', '')) > 20 else entry.get('password', 'N/A'),
                            entry.get('hashed_password', 'N/A')[:20] + "..." if entry.get('hashed_password') and len(entry.get('hashed_password', '')) > 20 else entry.get('hashed_password', 'N/A')
                        )
                    console.print(table)
                else:
                    console.print("[green]✓ No entries found in DeHashed[/green]")
            else:
                console.print(f"[yellow]⚠ DeHashed check failed (Status: {response.status_code})[/yellow]")

        except Exception as e:
            console.print(f"[red]✗ DeHashed lookup failed: {str(e)}[/red]")

    def check_intelx_email(self, email, api_key=None):
        """Search IntelligenceX for email occurrences using direct API"""

        if not api_key:
            console.print("[yellow]⚠ IntelX API key not provided, skipping...[/yellow]")
            return

        console.print("[bold blue]🔍 Checking IntelligenceX...[/bold blue]")

        try:
            # Try multiple API endpoints to improve connectivity
            api_endpoints = [
                "https://leakcheck.io/api/public",
                "https://leakcheck.io/api/v2",
                "https://free.intelx.io/",
                "https://2.intelx.io",
                "https://public.intelx.io",
                "https://www.intelx.io/apiv2"
            ]

            connected = False
            base_url = None

            for endpoint in api_endpoints:
                try:
                    # Test connection to endpoint
                    test_response = self.session.get(
                        f"{endpoint}/authenticate/info",
                        headers={'x-key': api_key},
                        timeout=10
                    )
                    if test_response.status_code == 200:
                        base_url = endpoint
                        connected = True
                        break
                except:
                    continue

            if not connected:
                console.print("[red]✗ Unable to connect to any IntelX API endpoints[/red]")
                console.print("[yellow]⚠ This could be due to network issues, an invalid API key, or API changes[/yellow]")
                console.print("[cyan]ℹ You can manually search for this email at https://intelx.io[/cyan]")
                return

            headers = {
                'x-key': api_key,
                'User-Agent': 'EmailOSINT/1.0'
            }

            # Create search
            search_data = {
                "term": email,
                "maxresults": 50,
                "media": 0,
                "target": 0,
                "timeout": 20,
                "datefrom": "",
                "dateto": "",
                "sort": 2,
                "terminate": []
            }

            # Initiate search with timeout and retry
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    search_response = self.session.post(
                        f"{base_url}/intelligent/search",
                        headers=headers,
                        json=search_data,
                        timeout=15
                    )
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        console.print(f"[yellow]⚠ Retrying IntelX connection (attempt {attempt+1}/{max_retries})...[/yellow]")
                        time.sleep(2)
                    else:
                        console.print("[red]✗ IntelX API connection failed after multiple attempts[/red]")
                        console.print(f"[cyan]ℹ Try manually searching at https://intelx.io/?s={quote(email)}[/cyan]")
                        return

            if search_response.status_code != 200:
                console.print(f"[red]✗ IntelX search request failed: {search_response.status_code}[/red]")
                if search_response.status_code == 401:
                    console.print("[yellow]⚠ Your API key might be invalid or expired[/yellow]")
                console.print(f"[cyan]ℹ Try manually searching at https://intelx.io/?s={quote(email)}[/cyan]")
                return

            try:
                search_data = search_response.json()
                search_id = search_data.get('id')
            except:
                console.print("[red]✗ Failed to parse IntelX response[/red]")
                return

            if not search_id:
                console.print("[red]✗ IntelX search ID not received[/red]")
                return

            # Wait for results to be ready
            console.print("[dim]Waiting for IntelX search results...[/dim]")
            time.sleep(5)  # Initial wait

            # Check search status
            status_url = f"{base_url}/intelligent/search/result"
            params = {
                'id': search_id,
                'limit': 20,  # Limit to 20 results
                'statistics': 1,
                'offset': 0
            }

            try:
                status_response = self.session.get(
                    status_url,
                    headers=headers,
                    params=params,
                    timeout=15
                )
            except Exception as e:
                console.print(f"[red]✗ Failed to retrieve IntelX results: {str(e)}[/red]")
                console.print(f"[cyan]ℹ Your search was initiated. Try viewing results at https://intelx.io[/cyan]")
                return

            if status_response.status_code != 200:
                console.print(f"[red]✗ IntelX result request failed: {status_response.status_code}[/red]")
                return

            try:
                result_data = status_response.json()
                records = result_data.get('records', [])
                total_records = result_data.get('totalhits', 0)
            except:
                console.print("[red]✗ Failed to parse IntelX results[/red]")
                return

            if total_records > 0 and records:
                console.print(f"[red]⚠ Found {total_records} record(s) in IntelX:[/red]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Type", style="red")
                table.add_column("Date", style="cyan")
                table.add_column("Source", style="yellow")
                table.add_column("Media", style="green")

                for record in records[:10]:
                    # Format date
                    date_str = "N/A"
                    if record.get("date"):
                        try:
                            date_timestamp = record.get("date") / 1000.0
                            date_str = time.strftime("%Y-%m-%d", time.gmtime(date_timestamp))
                        except:
                            date_str = str(record.get("date"))

                    table.add_row(
                        record.get("name", "N/A"),
                        date_str,
                        record.get("bucket", "N/A"),
                        record.get("media", "N/A")
                    )
                console.print(table)
            else:
                console.print("[green]✓ No matches found in IntelX[/green]")

        except Exception as e:
            console.print(f"[red]✗ IntelX lookup failed: {str(e)}[/red]")
            console.print(f"[cyan]ℹ Try manually searching at https://intelx.io/?s={quote(email)}[/cyan]")

    def check_leakcheck(self, email, api_key=None):
        """Check LeakCheck for breaches"""
        if not api_key:
            console.print("[yellow]⚠ LeakCheck API key not provided, skipping...[/yellow]")
            return

        console.print("[bold blue]🔍 Checking LeakCheck...[/bold blue]")

        try:
            url = f"https://leakcheck.io/api/public?check={quote(email)}"
            headers = {"X-API-Key": api_key}

            response = self.session.get(url, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get('found') and data.get('sources'):
                    console.print(f"[red]⚠ Found in {len(data['sources'])} source(s):[/red]")

                    for source in data['sources']:
                        console.print(f"[cyan]   • {source}[/cyan]")
                else:
                    console.print("[green]✓ No leaks found in LeakCheck[/green]")
            else:
                console.print(f"[yellow]⚠ LeakCheck failed (Status: {response.status_code})[/yellow]")

        except Exception as e:
            console.print(f"[red]✗ LeakCheck lookup failed: {str(e)}[/red]")

    def check_breach_directory(self, email):
        """Check various breach directories and paste sites with improved rate limiting"""
        console.print("[bold blue]🔍 Checking Breach Directories...[/bold blue]")

        found_count = 0

        # Single, more targeted search to avoid rate limits
        try:
            console.print("[dim]Searching paste sites...[/dim]")
            time.sleep(3)  # Initial delay

            with DDGS() as ddgs:
                # Combined query to reduce number of requests
                query = f'"{email}" (site:pastebin.com OR site:ghostbin.co OR site:rentry.co OR site:archive.org)'

                try:
                    results = list(ddgs.text(query, max_results=5))

                    if results:
                        console.print(f"[yellow]⚠ Found {len(results)} potential paste site matches[/yellow]")
                        for result in results:
                            console.print(f"[cyan]   • {result['title']} - {result['href']}[/cyan]")
                        found_count += len(results)
                    else:
                        console.print("[green]✓ No matches found in paste sites[/green]")

                except Exception as e:
                    console.print(f"[yellow]⚠ Paste site search failed (rate limited): {str(e)}[/yellow]")
                    # Fallback: provide manual search URLs
                    console.print("[dim]Manual search URLs:[/dim]")
                    console.print(f"[cyan]   Pastebin: https://pastebin.com/search?q={quote(email)}[/cyan]")
                    console.print(f"[cyan]   Archive.org: https://archive.org/search.php?query={quote(email)}[/cyan]")

        except Exception as e:
            console.print(f"[red]✗ Breach directory search failed: {str(e)}[/red]")

        if found_count == 0:
            console.print("[green]✓ No obvious matches in breach directories[/green]")

    def duckduckgo_email_search(self, email):
        """Enhanced DuckDuckGo search with multiple queries and rate limiting protection"""
        console.print("[bold blue]🔍 Performing DuckDuckGo searches...[/bold blue]")

        # Prioritized queries - most important first
        queries = [
            f'"{email}"',
            f'"{email}" breach OR leak OR dump',
            f'"{email}" site:pastebin.com OR site:ghostbin.co',
            f'"{email}" database OR hack OR compromise'
        ]

        all_results = []
        failed_queries = []

        for i, query in enumerate(queries):
            try:
                console.print(f"[dim]Searching ({i+1}/{len(queries)}): {query}[/dim]")

                # Increased delay and retry logic
                max_retries = 3
                retry_delay = 5

                for attempt in range(max_retries):
                    try:
                        # Create new DDGS instance for each query to avoid session issues
                        with DDGS() as ddgs:
                            results = list(ddgs.text(query, max_results=2))

                        if results:
                            for result in results:
                                result['query'] = query
                                all_results.append(result)
                            console.print(f"[green]   ✓ Found {len(results)} results[/green]")
                            break
                        else:
                            console.print(f"[yellow]   ⚠ No results for this query[/yellow]")
                            break

                    except Exception as e:
                        if attempt < max_retries - 1:
                            console.print(f"[yellow]   ⚠ Attempt {attempt + 1} failed, retrying in {retry_delay}s...[/yellow]")
                            time.sleep(retry_delay)
                            retry_delay += 2  # Exponential backoff
                        else:
                            console.print(f"[red]   ✗ Query failed after {max_retries} attempts: {str(e)}[/red]")
                            failed_queries.append(query)

                # Longer delay between queries
                if i < len(queries) - 1:  # Don't sleep after last query
                    console.print("[dim]   Waiting to avoid rate limits...[/dim]")
                    time.sleep(8)  # Increased from 2 to 8 seconds

            except KeyboardInterrupt:
                console.print("[yellow]\n⚠ Search interrupted by user[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]✗ Unexpected error with query '{query}': {str(e)}[/red]")
                failed_queries.append(query)
                continue

        # Report results
        if all_results:
            console.print(f"[green]✓ Found {len(all_results)} total results from DuckDuckGo[/green]")
        else:
            console.print("[yellow]⚠ No results found from DuckDuckGo searches[/yellow]")

        if failed_queries:
            console.print(f"[yellow]⚠ {len(failed_queries)} queries failed due to rate limiting[/yellow]")

        return all_results

    def print_duckduckgo_results(self, results):
        """Print DuckDuckGo results in organized format"""
        if not results:
            console.print("[yellow]No DuckDuckGo results found.[/yellow]")
            return

        # Group results by query
        grouped = {}
        for r in results:
            query = r.get("query", "Unknown")
            if query not in grouped:
                grouped[query] = []
            grouped[query].append(r)

        for query, items in grouped.items():
            if not items:
                continue

            console.print(f"\n[bold magenta]Results for: {query}[/bold magenta]")

            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Title", style="white", width=40)
            table.add_column("URL", style="blue", width=50)
            table.add_column("Description", style="dim white", width=60)

            for item in items[:3]:  # Limit to top 3 per query
                table.add_row(
                    item.get('title', 'N/A')[:40] + "..." if len(item.get('title', '')) > 40 else item.get('title', 'N/A'),
                    item.get('href', 'N/A'),
                    item.get('body', 'N/A')[:60] + "..." if len(item.get('body', '')) > 60 else item.get('body', 'N/A')
                )
            console.print(table)

    def check_social_media(self, email):
        """Check for social media accounts associated with email"""
        console.print("[bold blue]🔍 Checking Social Media Associations...[/bold blue]")

        # Basic social media search URLs
        social_sites = [
            ("Twitter/X", f"https://twitter.com/search?q={quote(email)}"),
            ("LinkedIn", f"https://www.linkedin.com/search/results/people/?keywords={quote(email)}"),
            ("GitHub", f"https://github.com/search?q={quote(email)}&type=users"),
            ("Reddit", f"https://www.reddit.com/search/?q={quote(email)}")
        ]

        for platform, url in social_sites:
            console.print(f"[cyan]   {platform}:[/cyan] {url}")

    def generate_report(self, email):
        """Generate a summary report"""
        console.print("\n" + "="*80)
        console.print(Panel.fit(
            f"[bold]OSINT Report for: {email}[/bold]\n"
            f"[dim]Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            border_style="green"
        ))

    def run_search(self, email, config=None):
        """Main search function that orchestrates all checks"""
        if config is None:
            config = load_config()

        console.print(f"[bold green]🎯 Starting comprehensive OSINT search for:[/bold green] [cyan]{email}[/cyan]\n")

        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            console.print("[red]✗ Invalid email format provided[/red]")
            return

        # Check if DuckDuckGo searches should be skipped
        skip_ddg = config.get('skip_duckduckgo', False)
        if skip_ddg:
            console.print("[yellow]⚠ DuckDuckGo searches disabled in config[/yellow]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            # Gravatar lookup
            task = progress.add_task("[cyan]Checking Gravatar...", total=None)
            self.gravatar_lookup(email)
            progress.remove_task(task)

            # Have I Been Pwned
            task = progress.add_task("[cyan]Checking breaches...", total=None)
            self.check_haveibeenpwned(email)
            progress.remove_task(task)

            # IntelligenceX
            task = progress.add_task("[cyan]Checking IntelX...", total=None)
            self.check_intelx_email(email, config.get('intelx_api_key'))
            progress.remove_task(task)

            # DeHashed
            task = progress.add_task("[cyan]Checking DeHashed...", total=None)
            self.check_dehashed(email, config.get('dehashed_api_key'))
            progress.remove_task(task)

            # LeakCheck
            task = progress.add_task("[cyan]Checking LeakCheck...", total=None)
            self.check_leakcheck(email, config.get('leakcheck_api_key'))
            progress.remove_task(task)

            # Breach directories (only if DDG not disabled)
            if not skip_ddg:
                task = progress.add_task("[cyan]Checking breach directories...", total=None)
                self.check_breach_directory(email)
                progress.remove_task(task)

            # Social media
            task = progress.add_task("[cyan]Checking social media...", total=None)
            self.check_social_media(email)
            progress.remove_task(task)

            # DuckDuckGo search (only if not disabled)
            if not skip_ddg:
                task = progress.add_task("[cyan]Performing web searches...", total=None)
                ddg_results = self.duckduckgo_email_search(email)
                self.print_duckduckgo_results(ddg_results)
                progress.remove_task(task)
            else:
                console.print("[yellow]⚠ Skipping DuckDuckGo searches (disabled in config)[/yellow]")

        # Generate final report
        self.generate_report(email)

        console.print(f"\n[bold green]✅ Search completed for {email}[/bold green]")
        console.print("[dim]Remember to verify any findings through additional sources[/dim]")


def load_config():
    """Load API keys from config file"""
    config = {}

    # Look for config file in same directory as script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, '..', 'config.json')

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        console.print("[yellow]⚠ No config.json found. API-dependent features will be limited.[/yellow]")
        console.print("[dim]Create a config.json file with your API keys for full functionality.[/dim]\n")
    except Exception as e:
        console.print(f"[red]✗ Error loading config: {str(e)}[/red]")

    return config


def search_by_email(email):
    """
    Main function to be called from main.py

    Args:
        email (str): Email address to investigate
    """
    osint_tool = EmailOSINT()
    osint_tool.run_search(email)


# For backward compatibility with your existing code
def gravatar_lookup(email):
    """Backward compatibility function"""
    osint_tool = EmailOSINT()
    osint_tool.gravatar_lookup(email)


def check_intelx_email(email, api_key=None):
    """Backward compatibility function"""
    osint_tool = EmailOSINT()
    osint_tool.check_intelx_email(email, api_key)


def duckduckgo_email_search(email):
    """Backward compatibility function"""
    osint_tool = EmailOSINT()
    return osint_tool.duckduckgo_email_search(email)


def print_duckduckgo_results(results):
    """Backward compatibility function"""
    osint_tool = EmailOSINT()
    osint_tool.print_duckduckgo_results(results)

