import os
import json
from typing import Dict, Any
import google.generativeai as genai
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
        console.print("[yellow]⚠ No config.json found. Gemini analysis will be disabled.[/yellow]")
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
- Enable Gemini API for full analysis
- Verify your API quota and billing
- Review collected data manually"""

class GeminiAnalyzer:
    def __init__(self, test_mode=True):
        self.config = load_config()
        self.api_key = self.config.get('gemini_api_key')
        self.test_mode = test_mode
        
        if not self.api_key and not self.test_mode:
            raise ValueError("Gemini API key not found in config.json")
            
        if not self.test_mode:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-pro')

    async def analyze_findings(self, data: Dict[str, Any]) -> str:
        """Analyze OSINT findings using Gemini or fallback to mock analysis"""
        if self.test_mode:
            console.print("[yellow]⚠ Running in test mode - using mock analysis[/yellow]")
            return get_mock_analysis(data)
            
        prompt = self._create_analysis_prompt(data)
        
        try:
            response = await self.model.generate_content_async(prompt)
            return response.text
        except Exception as e:
            console.print(f"[red]✗ Gemini API call failed: {str(e)}[/red]")
            console.print("[yellow]ℹ Falling back to mock analysis[/yellow]")
            return get_mock_analysis(data)

    def _create_analysis_prompt(self, data: Dict[str, Any]) -> str:
        return f"""Analyze the following OSINT (Open Source Intelligence) data and provide detailed insights:
        
Data collected: {data}

Provide a structured analysis with:
1. Key findings and patterns in the data
2. Potential security implications and risks
3. Recommended actions and mitigations
4. Data exposure assessment

Format the response in a clear, professional manner."""