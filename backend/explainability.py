import shap
import numpy as np
import pandas as pd

# Human readable explanations
FEATURE_DESCRIPTIONS = {
    "having_IP_Address": "URL contains IP address",
    "URL_Length": "URL length is suspiciously high",
    "Shortining_Service": "Shortened URL detected",
    "having_At_Symbol": "URL contains @ symbol",
    "double_slash_redirecting": "Double slash redirection found",
    "Prefix_Suffix": "Hyphen used in domain name",
    "having_Sub_Domain": "Too many subdomains detected",
    "SSLfinal_State": "SSL certificate is suspicious or missing"
}


class PhishingExplainer:

    def __init__(self, model, feature_names):

        self.model = model
        self.feature_names = feature_names

        # Create SHAP explainer
        self.explainer = shap.TreeExplainer(model)

    def explain(self, features, top_n=5):

        """
        features -> scaled feature vector
        """

        # Calculate shap values
        shap_values = self.explainer.shap_values(features)

        # For binary classification
        if isinstance(shap_values, list):
            shap_values = shap_values[1]

        shap_values = shap_values[0]

        explanations = []

        # Pair feature names with SHAP scores
        feature_impacts = list(zip(
            self.feature_names,
            shap_values
        ))

        # Sort by absolute contribution
        feature_impacts.sort(
            key=lambda x: abs(x[1]),
            reverse=True
        )

        # Select top important features
        for feature, impact in feature_impacts[:top_n]:

            description = FEATURE_DESCRIPTIONS.get(
                feature,
                feature
            )

            explanations.append({
                "feature": feature,
                "reason": description,
                "impact_score": round(float(impact), 4)
            })

        return explanations