"""Seeded Random Forest behavior classifier and descriptive K-Means clustering.

The classifier is trained only on deterministic synthetic scenarios. Its output
is a demo triage signal, not ground truth or an independently validated detector.
Clustering runs over observed attacker feature vectors and reports descriptive
cluster labels rather than asserted actor identities.
"""
from __future__ import annotations

from typing import Any

try:
    import numpy as np
    from sklearn.cluster import KMeans
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:  # Keep the honeypot online if optional model dependencies are absent.
    np = None
    KMeans = RandomForestClassifier = make_pipeline = StandardScaler = None
    ML_AVAILABLE = False

from behaviour import engineer_features

FEATURE_ORDER = ["events_per_minute", "failed_login_count", "unique_endpoints", "unique_ports",
                 "command_count", "suspicious_command_count", "decoy_resource_access", "session_duration",
                 "repeated_action_ratio", "attack_frequency", "historical_risk", "previous_attack_count",
                 "service_diversity", "suspicious_event_count", "login_attempt_count"]
CLASSES = ["normal", "reconnaissance", "brute_force", "credential_attack", "suspicious_access",
           "command_execution", "exploitation_attempt"]


def _vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]


def _synthetic_training_data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(271828)
    centers = {
        "normal": [1, 0, 2, 0, 0, 0, 0, 12, .1, 0, 3, 0, 1, 0, 0],
        "reconnaissance": [12, 0, 18, 8, 0, 0, 0, 30, .2, 10, 45, 12, 2, 6, 0],
        "brute_force": [8, 16, 2, 0, 0, 0, 0, 90, .8, 8, 70, 20, 1, 18, 20],
        "credential_attack": [5, 8, 6, 0, 0, 0, 3, 120, .5, 4, 72, 8, 1, 12, 10],
        "suspicious_access": [4, 0, 5, 0, 0, 0, 4, 35, .3, 3, 60, 5, 1, 8, 0],
        "command_execution": [4, 0, 4, 0, 8, 5, 0, 150, .2, 3, 80, 7, 2, 10, 0],
        "exploitation_attempt": [5, 0, 7, 0, 0, 0, 1, 40, .2, 4, 88, 8, 1, 9, 0],
    }
    x, y = [], []
    for label_index, label in enumerate(CLASSES):
        center = np.array(centers[label], dtype=float)
        scale = np.maximum(np.abs(center) * .18, .5)
        for sample in rng.normal(center, scale, size=(100, len(FEATURE_ORDER))):
            x.append(np.maximum(sample, 0))
            y.append(label_index)
    return np.asarray(x), np.asarray(y)


class BehaviorModel:
    def __init__(self):
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn/numpy are unavailable")
        x, y = _synthetic_training_data()
        self.model = make_pipeline(StandardScaler(), RandomForestClassifier(
            n_estimators=160, class_weight="balanced", random_state=41, min_samples_leaf=2))
        self.model.fit(x, y)
        self.algorithm = "RandomForestClassifier + StandardScaler"
        self.training_data = "seeded synthetic behavior scenarios"

    def classify(self, features: dict[str, float]) -> dict[str, Any]:
        vector = np.asarray([_vector(features)])
        probabilities = self.model.predict_proba(vector)[0]
        index = int(np.argmax(probabilities))
        return {"label": CLASSES[index], "confidence": float(probabilities[index]),
                "model": "RandomForestClassifier", "training_data": "seeded synthetic behavior scenarios"}

    @staticmethod
    def cluster_profiles(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
        valid = [profile for profile in profiles if profile.get("events")]
        if len(valid) < 2:
            return []
        matrix = np.asarray([_vector(engineer_features(p["events"])) for p in valid])
        count = min(4, len(valid))
        labels = KMeans(n_clusters=count, n_init=10, random_state=17).fit_predict(StandardScaler().fit_transform(matrix))
        grouped: dict[int, list[dict[str, Any]]] = {}
        for label, profile in zip(labels, valid):
            grouped.setdefault(int(label), []).append(profile)
        output = []
        for cluster_id, members in sorted(grouped.items()):
            feature = engineer_features(members[0]["events"])
            if feature["failed_login_count"] >= 3:
                description = "brute-force-like behavior"
            elif feature["unique_endpoints"] >= 8:
                description = "reconnaissance-like behavior"
            elif feature["decoy_resource_access"]:
                description = "credential/decoy hunting behavior"
            else:
                description = "mixed observed behavior"
            output.append({"cluster_id": cluster_id, "description": description,
                           "member_ips": [p["source_ip"] for p in members], "ground_truth": False})
        return output


class RuleFallbackModel:
    """Small deterministic fallback used only when the optional ML stack is missing."""
    algorithm = "transparent-rule-fallback"
    training_data = "not applicable"

    def classify(self, features: dict[str, float]) -> dict[str, Any]:
        if features.get("suspicious_command_count", 0):
            label = "command_execution"
        elif features.get("failed_login_count", 0) >= 3:
            label = "brute_force"
        elif features.get("decoy_resource_access", 0):
            label = "credential_attack"
        elif features.get("unique_endpoints", 0) >= 8:
            label = "reconnaissance"
        elif features.get("historical_risk", 0) >= 80:
            label = "exploitation_attempt"
        elif features.get("suspicious_event_count", 0):
            label = "suspicious_access"
        else:
            label = "normal"
        return {"label": label, "confidence": 0.5, "model": self.algorithm,
                "training_data": self.training_data}

    @staticmethod
    def cluster_profiles(_profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return []


_DEFAULT_MODEL: BehaviorModel | None = None


def get_model() -> BehaviorModel | RuleFallbackModel:
    global _DEFAULT_MODEL
    if _DEFAULT_MODEL is None:
        _DEFAULT_MODEL = BehaviorModel() if ML_AVAILABLE else RuleFallbackModel()
    return _DEFAULT_MODEL
