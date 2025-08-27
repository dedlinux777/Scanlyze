import vt
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os

VIRUSTOTAL_API_KEY = "9a3004c50d65c006b7d0bcb18f0eb125bb7a73700d42d9a8102f082755bba58b"

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# VirusTotal (File Scan) 
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

# VirusTotal (URL Scan)
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

# Flask Routes
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

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
