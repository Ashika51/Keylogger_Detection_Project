from flask import Flask, jsonify
import psutil

app = Flask(__name__)

# Check for known keylogger process (Refog example)
def detect_keylogger():
    keylogger_names = ["refog.exe", "refog", "recovery64.exe"]  # Add more if needed
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'].lower() in keylogger_names:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

@app.route("/check")
def check_keylogger():
    found = detect_keylogger()
    if found:
        return jsonify({"status": "found", "message": "⚠️ Keylogger Detected (Refog)!"})
    else:
        return jsonify({"status": "clean", "message": "✅ No Keylogger Detected."})

if __name__ == "__main__":
    app.run(debug=True)
