# Scanalyze

Scanalyze is a web application for gathering information about domains and scanning files/URLs for malware using various APIs.

## Features

- **WHOIS Lookup:** Get domain registration and registrar details using the WHOISFreaks API.
- **DNS Records:** Retrieve DNS records (A, NS, MX, TXT, etc.) for a domain.
- **GeoIP Lookup:** Find geolocation information for a domain or IP.
- **VirusTotal File Scan:** Scan uploaded files for malware using VirusTotal.
- **VirusTotal URL Scan:** Scan URLs for threats using VirusTotal.

## Requirements

- Python 3.7+
- See `requirements.txt` for all dependencies.

## Setup

1. **Clone the repository** (or copy the files to your project directory).

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set API Keys:**
   - Edit `app.py` and replace the placeholders for `WHOISFREAKS_API_KEY` and `VIRUSTOTAL_API_KEY` with your own API keys.

4. **Run the app:**
   ```bash
   python app.py
   ```

5. **Access the app:**
   - Open your browser and go to `http://127.0.0.1:5000/`

## File Structure

- `app.py` - Main Flask application.
- `requirements.txt` - Python dependencies.
- `test-api.py` - Script for testing VirusTotal API.
- `uploads/` - Directory for uploaded files.
- `templates/` - HTML templates (not included here).

## Notes

- Make sure you have valid API keys for WHOISFreaks and VirusTotal.
- Do not share your API keys publicly.
- For production, set `debug=False` in `app.py`.

## License

This project is for educational and personal use.
