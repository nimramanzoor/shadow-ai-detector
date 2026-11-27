import re
import json
from collections import defaultdict

LOG_FILE = "proxy_logs.txt"
REPORT_FILE = "shadow_ai_report.json"
PAYLOAD_THRESHOLD = 20000  # Flag any upload larger than 20KB

AI_ENDPOINTS = [
    r"openai\.com", r"chatgpt\.com", r"anthropic\.com",
    r"claude\.ai", r"huggingface\.co", r"gemini\.google\.com"
]

ai_regex = re.compile(r"(" + "|".join(AI_ENDPOINTS) + r")", re.IGNORECASE)

def analyze_logs(file_path):
    detections = defaultdict(list)
    
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                # Updated Regex to capture the payload size at the end of the line
                match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+(?:GET|POST|PUT|DELETE)\s+(https?://\S+)\s+\d+\s+(\d+)", line)
                
                if match:
                    ip_address = match.group(1)
                    url = match.group(2)
                    payload_size = int(match.group(3))
                    
                    if ai_regex.search(url):
                        # Determine if this is a massive data upload
                        risk_level = "CRITICAL (Data Leak)" if payload_size > PAYLOAD_THRESHOLD else "Medium (Usage)"
                        
                        detections[ip_address].append({
                            "line_number": line_number,
                            "url": url,
                            "payload_bytes": payload_size,
                            "risk_level": risk_level,
                            "raw_log": line.strip()
                        })
                        
    except FileNotFoundError:
        print(f"[!] Error: '{file_path}' not found.")
        return None

    return detections

def generate_report(detections, output_file):
    if not detections:
        print("[*] No Shadow AI traffic detected. Network is secure.")
        return
        
    total_hits = sum(len(hits) for hits in detections.values())
    print(f"[!] Alert: Detected {total_hits} unauthorized AI requests.")
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(detections, f, indent=4)
        
    print(f"[*] Detailed JSON report saved to {output_file}")

if __name__ == "__main__":
    print("[*] Starting Shadow AI Exfiltration Detector...")
    results = analyze_logs(LOG_FILE)
    if results is not None:
        generate_report(results, REPORT_FILE)