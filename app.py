import socket
import dns.resolver
import requests
import vt
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os

WHOISFREAKS_API_KEY = "ffe4176e0c304848b986d7c3eac21f7e"
VIRUSTOTAL_API_KEY = "9a3004c50d65c006b7d0bcb18f0eb125bb7a73700d42d9a8102f082755bba58b"

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- WHOISFreaks ----------------
def get_whoisfreaks_info(domain):
    url = (
        f"https://api.whoisfreaks.com/v1.0/whois"
        f"?apiKey={WHOISFREAKS_API_KEY}&whois=live&domainName={domain}&format=json"
    )
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") is True:
                registrar = data.get("domain_registrar", {})
                return {
                    "domain_name": data.get("domain_name"),
                    "whois_server": data.get("whois_server"),
                    "domain_registered": data.get("domain_registered"),
                    "create_date": data.get("create_date"),
                    "update_date": data.get("update_date"),
                    "expiry_date": data.get("expiry_date"),
                    "registrar_name": registrar.get("registrar_name"),
                    "registrar_email": registrar.get("email_address"),
                    "registrar_phone": registrar.get("phone_number"),
                    "registrar_website": registrar.get("website_url"),
                }
            else:
                return {"error": "WHOISFreaks API returned no data."}
        else:
            return {"error": f"WHOISFreaks API error: HTTP {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": f"Error contacting WHOISFreaks API: {str(e)}"}

# ---------------- DNS ----------------
def get_dns_info(domain):
    dns_data = {}
    record_types = ['A', 'NS', 'MX', 'TXT', 'CNAME', 'PTR', 'SOA', 'SRV']
    for rec_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, rec_type)
            dns_data[rec_type] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            pass
    return dns_data

# ---------------- GEOIP ----------------
def get_geoip_info(target):
    try:
        ip_address = socket.gethostbyname(target)
        response = requests.get(f"https://geolocation-db.com/json/{ip_address}").json()
        if response.get('country_code') == 'Not found':
            return {"error": "Geolocation not found for this IP."}
        return {
            "ip_address": ip_address,
            "country": response.get('country_name'),
            "state": response.get('state'),
            "city": response.get('city'),
            "latitude": response.get('latitude'),
            "longitude": response.get('longitude')
        }
    except Exception as e:
        return {"error": str(e)}

# ---------------- VirusTotal (File Scan) ----------------
def scan_file_with_virustotal(filepath):
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif hasattr(obj, "items"):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(i) for i in obj]
        else:
            return obj
    try:
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            with open(filepath, "rb") as f:
                analysis = client.scan_file(f, wait_for_completion=True)
                return {
                    "id": analysis.id,
                    "status": analysis.status,
                    "stats": make_serializable(analysis.stats) if hasattr(analysis, "stats") else {},
                    "results": make_serializable(analysis.results) if hasattr(analysis, "results") else {}
                }
    except Exception as e:
        return {"error": f"VirusTotal file scan error: {str(e)}"}

# ---------------- VirusTotal (URL Scan) ----------------
def scan_url_with_virustotal(url_str):
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif hasattr(obj, "items"):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(i) for i in obj]
        else:
            return obj
    try:
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            analysis = client.scan_url(url_str, wait_for_completion=True)
            return {
                "id": analysis.id,
                "status": analysis.status,
                "stats": make_serializable(analysis.stats) if hasattr(analysis, "stats") else {},
                "results": make_serializable(analysis.results) if hasattr(analysis, "results") else {}
            }
    except Exception as e:
        return {"error": f"VirusTotal URL scan error: {str(e)}"}

# ---------------- Flask Routes ----------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/gather", methods=["POST"])
def gather():
    domain = request.form.get("domain")
    results = {}

    if domain:
        results['whois_info'] = get_whoisfreaks_info(domain)
        results['dns_records'] = get_dns_info(domain)
        results['geoip_info'] = get_geoip_info(domain)

    return render_template("results.html", results=results)

@app.route("/scan_file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return render_template("results.html", results={"virustotal_file_scan": {"error": "No file uploaded"}})
    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return render_template("results.html", results={"virustotal_file_scan": {"error": "Empty filename"}})
    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    uploaded_file.save(filepath)
    result = scan_file_with_virustotal(filepath)
    return render_template("results.html", results={"virustotal_file_scan": result})

@app.route("/scan_url", methods=["POST"])
def scan_url():
    url_str = request.form.get("url_to_scan")
    if not url_str:
        return render_template("results.html", results={"virustotal_url_scan": {"error": "No URL provided"}})
    result = scan_url_with_virustotal(url_str)
    return render_template("results.html", results={"virustotal_url_scan": result})

if __name__ == "__main__":
    app.run(debug=True)
