from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
from explainability import PhishingExplainer
import sqlite3
import os

DB_PATH = 'stats.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            visitors INTEGER DEFAULT 0,
            scans INTEGER DEFAULT 0,
            phishing INTEGER DEFAULT 0,
            legitimate INTEGER DEFAULT 0,
            medium INTEGER DEFAULT 0
        )
    ''')
    c.execute('INSERT OR IGNORE INTO stats (id, visitors, scans, phishing, legitimate, medium) VALUES (1, 0, 0, 0, 0, 0)')
    conn.commit()
    conn.close()

init_db()

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM stats WHERE id = 1')
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def increment_stat(column):
    valid_columns = ['visitors', 'scans', 'phishing', 'legitimate', 'medium']
    if column in valid_columns:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(f'UPDATE stats SET {column} = {column} + 1 WHERE id = 1')
        conn.commit()
        conn.close()

# Import your custom files
from featureextraction import extract_features


# -----------------------------
# Initialize Flask App
# -----------------------------
app = Flask(__name__)
CORS(app)

# -----------------------------
# Load Trained Model
# -----------------------------
model = joblib.load("phishing_model.pkl")

# -----------------------------
# Feature Names
# (same order used during training)
# -----------------------------
feature_names = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
]

# -----------------------------
# Initialize Explainer
# -----------------------------
explainer = PhishingExplainer(model, feature_names)

# -----------------------------
# Home Route
# -----------------------------
@app.route("/")
def home():
    increment_stat('visitors')
    return render_template("dashboard.html")


@app.route("/health")
def health():
    return jsonify({
        "message": "Phishing Detection API is running"
    })

# -----------------------------
# Prediction Route
# -----------------------------
@app.route("/predict", methods=["POST"])
def predict():

    try:
        # Get URL from frontend
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "error": "URL not provided"
            }), 400

        url = data["url"].strip()

        if not url:
            return jsonify({
                "error": "URL not provided"
            }), 400

        # -----------------------------
        # Feature Extraction
        # -----------------------------
        features = extract_features(url)

        # Convert extracted features into model input in training order
        features_array = np.array(
            [[features[name] for name in feature_names]],
            dtype=float
        )

        # -----------------------------
        # Prediction
        # -----------------------------
        prediction = int(model.predict(features_array)[0])

        # Probability
        probability = model.predict_proba(features_array)[0]

        threat_level = float(round(probability[1] * 100, 2))

        # -----------------------------
        # Explainability
        # -----------------------------
        explanation = explainer.explain(features_array)

        # -----------------------------
        # Convert Prediction
        # -----------------------------
        if threat_level >= 70:
            result = "Phishing"
            increment_stat('phishing')
        elif threat_level >= 30:
            result = "Medium Legitimate"
            increment_stat('medium')
        else:
            result = "Legitimate"
            increment_stat('legitimate')

        increment_stat('scans')

        # -----------------------------
        # Final Response
        # -----------------------------
        response = {
            "url": url,
            "prediction": result,
            "threat_level": threat_level,
            "features": features,

            "explanation": explanation
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
