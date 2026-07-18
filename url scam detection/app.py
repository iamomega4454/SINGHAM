from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
from explainability import PhishingExplainer
import os

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
        elif threat_level >= 30:
            result = "Medium Legitimate"
        else:
            result = "Legitimate"

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
