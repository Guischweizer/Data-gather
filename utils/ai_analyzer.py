import os
import json
from openai import AsyncOpenAI
from typing import Dict, Any
from rich.console import Console

console = Console()

def load_config():
    """Load configuration from config file"""
    config = {}
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, '..', 'config.json')

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        console.print("[yellow]⚠ No config.json found. OpenAI analysis will be disabled.[/yellow]")
    except Exception as e:
        console.print(f"[red]✗ Error loading config: {str(e)}[/red]")

    return config

def get_mock_analysis(data: Dict[str, Any]) -> str:
    """Provide a mock analysis for testing purposes"""
    return f"""[TEST MODE] Analysis of collected data:

1. Key Findings:
- Data collection completed successfully
- Found {len(data)} main data points
- Sources checked: {', '.join(data.keys())}

2. Potential Security Implications:
- This is a mock analysis for testing
- No real security assessment performed

3. Recommended Actions:
- Enable OpenAI API for full analysis
- Verify your API quota and billing
- Review collected data manually"""

class AIAnalyzer:
    def __init__(self, test_mode=True):
        self.config = load_config()
        self.api_key = self.config.get('openai_api_key')
        self.test_mode = test_mode
        
        if not self.api_key and not self.test_mode:
            raise ValueError("OpenAI API key not found in config.json")
            
        if not self.test_mode:
            self.client = AsyncOpenAI(api_key=self.api_key)

    async def analyze_findings(self, data: Dict[str, Any]) -> str:
        """Analyze OSINT findings using GPT or fallback to mock analysis"""
        if self.test_mode:
            console.print("[yellow]⚠ Running in test mode - using mock analysis[/yellow]")
            return get_mock_analysis(data)
            
        prompt = self._create_analysis_prompt(data)
        
        try:
            response = await self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an OSINT analysis assistant. Analyze the provided data and give insights."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            console.print(f"[red]✗ OpenAI API call failed: {str(e)}[/red]")
            console.print("[yellow]ℹ Falling back to mock analysis[/yellow]")
            return get_mock_analysis(data)

    def _create_analysis_prompt(self, data: Dict[str, Any]) -> str:
        return f"""Please analyze the following OSINT data and provide key insights:
        
Data collected: {data}

Please provide:
1. Key findings
2. Potential security implications
3. Recommended actions"""