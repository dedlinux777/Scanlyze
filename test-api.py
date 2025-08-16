import requests
import vt
import json



VIRUSTOTAL_API_KEY = "9a3004c50d65c006b7d0bcb18f0eb125bb7a73700d42d9a8102f082755bba58b"

def make_serializable(obj):
    # Recursively convert WhistleBlowerDict and similar objects to dict/list
    if isinstance(obj, dict):
        return {k: make_serializable(v) for k, v in obj.items()}
    elif hasattr(obj, "items"):
        # For WhistleBlowerDict or similar mapping types
        return {k: make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_serializable(i) for i in obj]
    else:
        return obj

def scan_url_with_virustotal(url_str):
    try:
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            analysis = client.scan_url(url_str, wait_for_completion=True)
            print("Type of analysis.stats:", type(analysis.stats))
            print("Type of analysis.results:", type(analysis.results))
            # Recursively convert to serializable
            stats = make_serializable(analysis.stats) if hasattr(analysis, "stats") else {}
            results = make_serializable(analysis.results) if hasattr(analysis, "results") else {}
            data = {
                "id": analysis.id,
                "status": analysis.status,
                "stats": stats,
                "results": results
            }
            print("Data to serialize:", data)
            print("Trying to serialize to JSON...")
            print(json.dumps(data, indent=2))
            return data
    except Exception as e:
        print("Error:", e)
        return {"error": str(e)}

if __name__ == "__main__":
    # Test with a public, non-private URL
    scan_url_with_virustotal("https://www.hackthissite.org/")
