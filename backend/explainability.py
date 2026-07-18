import shap
import numpy as np
import pandas as pd

# Human readable explanations - URL Phishing
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

# Human readable explanations - Malware PE Features
MALWARE_FEATURE_DESCRIPTIONS = {
    "MajorLinkerVersion": "Linker version used to compile the file",
    "MinorOperatingSystemVersion": "Minimum OS minor version required",
    "MajorSubsystemVersion": "Windows subsystem major version",
    "SizeOfStackReserve": "Stack memory reserved for execution",
    "TimeDateStamp": "Compilation timestamp of the executable",
    "MajorOperatingSystemVersion": "Minimum OS major version required",
    "Characteristics": "File characteristic flags (e.g. executable, DLL)",
    "ImageBase": "Preferred memory load address of the file",
    "Subsystem": "Windows subsystem type (GUI, Console, etc.)",
    "MinorImageVersion": "Image minor version number",
    "MinorSubsystemVersion": "Windows subsystem minor version",
    "SizeOfInitializedData": "Size of initialized data section",
    "DllCharacteristics": "DLL security feature flags (ASLR, DEP, etc.)",
    "DirectoryEntryExport": "Whether the file exports functions (DLL indicator)",
    "ImageDirectoryEntryExport": "Size of the export directory",
    "CheckSum": "PE checksum for file integrity verification",
    "DirectoryEntryImportSize": "Size of the import directory (API usage indicator)",
    "SectionMaxChar": "Number of sections in the PE file",
    "MajorImageVersion": "Image major version number",
    "AddressOfEntryPoint": "Memory address where execution begins",
    "SectionMinEntropy": "Minimum section entropy (low entropy = plaintext code)",
    "SizeOfHeaders": "Size of all PE headers combined",
    "SectionMinVirtualsize": "Smallest virtual section size in memory",
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


class MalwareExplainer:

    FEATURE_NAMES = [
        'MajorLinkerVersion', 'MinorOperatingSystemVersion', 'MajorSubsystemVersion',
        'SizeOfStackReserve', 'TimeDateStamp', 'MajorOperatingSystemVersion',
        'Characteristics', 'ImageBase', 'Subsystem', 'MinorImageVersion',
        'MinorSubsystemVersion', 'SizeOfInitializedData', 'DllCharacteristics',
        'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'CheckSum',
        'DirectoryEntryImportSize', 'SectionMaxChar', 'MajorImageVersion',
        'AddressOfEntryPoint', 'SectionMinEntropy', 'SizeOfHeaders',
        'SectionMinVirtualsize'
    ]

    def __init__(self, model):
        self.model = model
        self.explainer = shap.TreeExplainer(model)

    def explain(self, features_df, top_n=7):
        """
        features_df -> pandas DataFrame with PE feature columns
        Returns a list of dicts with feature name, description, impact score, and direction.

        Handles both SHAP API formats:
          - Old (< 0.40): list of arrays per class -> shap_values[1] is (n_samples, n_features)
          - New (>= 0.40): single ndarray of shape (n_samples, n_features, n_classes)
        """
        shap_values = self.explainer.shap_values(features_df)

        if isinstance(shap_values, list):
            # Old API: list[class_idx] -> (n_samples, n_features)
            sv = np.array(shap_values[1][0], dtype=float)
        elif hasattr(shap_values, 'ndim') and shap_values.ndim == 3:
            # New API: (n_samples, n_features, n_classes) — pick malware class (index 1)
            sv = np.array(shap_values[0, :, 1], dtype=float)
        else:
            sv = np.array(shap_values[0], dtype=float)

        # Flatten to guarantee 1D
        sv = sv.flatten()

        feature_names = list(features_df.columns)
        feature_impacts = list(zip(feature_names, sv.tolist()))

        # Sort by absolute SHAP value (all values are now plain Python floats)
        feature_impacts.sort(key=lambda x: abs(x[1]), reverse=True)

        explanations = []
        for feature, impact in feature_impacts[:top_n]:
            impact_f = float(impact)
            explanations.append({
                "feature": feature,
                "reason": MALWARE_FEATURE_DESCRIPTIONS.get(feature, feature),
                "impact_score": round(impact_f, 5),
                "direction": "malware" if impact_f > 0 else "safe"
            })

        return explanations