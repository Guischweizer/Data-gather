# Data Gather – OSINT Research Tool

**Purpose**:  
This project is intended for educational and research purposes only. It is a tool designed to help cybersecurity students and professionals explore techniques for open-source intelligence (OSINT) gathering on email addresses and names.

> ⚠️ **DISCLAIMER**:  
> This tool must be used responsibly and only on targets you have permission to research. Do not use this for illegal or unethical purposes. The developer assumes no responsibility for misuse.

---

## 🔍 Features

- **Gravatar Lookup** – Retrieve public profile data from [Gravatar](https://gravatar.com) using email hash.
- **DuckDuckGo Search** – Perform OSINT keyword-based searches for names or emails.
- **IntelligenceX Integration** – Check if an email appears in breaches or leaks.
- **Dual AI Analysis** – Choose between OpenAI GPT or Google's Gemini for intelligent analysis of findings
- **Rich Terminal Output** – Uses `rich` for clean, formatted output.
- **Docker-ready** – Easily containerizable for isolated environments.
- **Command-line Interface** – Run with simple flags like `--email` or `--name`.

---

## ⚙️ Installation

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/data-gather.git
cd data-gather
```

### 2. Set up a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash 
pip install -r requirements.txt
```

### 4. Create a configuration file
```bash
touch config.json
```

### 5. Add the keys to config file
```json
{
  "skip_duckduckgo": true,
  "intelx_api_key": "xxxxxxxxxxxxxxx",
  "dehashed_api_key": "email:password",
  "leakcheck_api_key": "your_key_here",
  "openai_api_key": "your-openai-api-key-here",
  "gemini_api_key": "your-gemini-api-key-here"
}
```

## 🚀 Usage

### Run with Python
```bash 
# Standard search with OpenAI analysis (default)
python main.py --email someone@example.com

# Search with Gemini AI analysis
python main.py --email someone@example.com --ai gemini

# Search by name with specific AI model
python main.py --name "John Doe" --ai openai

# Run in test mode (no API calls)
python main.py --email someone@example.com --test
```

### Command Line Arguments
- `--email`: Target email address to investigate
- `--name`: Full name to search for
- `--test`: Run in test mode without making API calls (uses mock data)
- `--ai`: Choose AI service for analysis (options: 'openai' or 'gemini', default: openai)

### Make it globally executable
```bash
sudo ln -s /opt/data-gather/main.py /usr/local/bin/data-gather
chmod +x /opt/data-gather/main.py
```

### Run globally
```bash
data-gather --email someone@example.com
data-gather --name "John Doe"
```

## 🔐 Ethics and Legality

### This tool is strictly for:

- Security testing with authorization

- Educational demonstrations

- Researching your own digital footprint

## ❌ You must not:
- Use it on individuals or systems without consent

- Attempt to exploit or target systems using gathered data

📫 Contributions
Feel free to open issues or submit pull requests to enhance features, add new data sources, or improve output formatting.

📝 License
This project is licensed under the MIT License.

