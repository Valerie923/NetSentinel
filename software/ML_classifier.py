"""
ml_classifier.py
Machine learning layer for NetSentinel.
Trains a Random Forest classifier on simulated network traffic
to classify attack types output by the Verilog hardware layer.

Attack type encoding (matches Verilog packet_filter.v):
  0 = Clean
  1 = Suspicious Port
  2 = Port Scan
  3 = DDoS
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from simulate_verilog_output import generate_traffic, ATTACK_LABELS
import joblib
import os

MODEL_PATH = "models/netsentinel_classifier.pkl"


def extract_features(packets):
    """
    Extract numerical features from packet data for ML classification.
    Features mirror what the Verilog hardware layer exposes.
    """
    rows = []
    for p in packets:
        rows.append({
            "dest_port": p["dest_port"],
            "pkt_count": p["pkt_count"],
            "is_tcp": 1 if p["protocol"] == "TCP" else 0,
            "is_system_port": 1 if p["dest_port"] < 1024 else 0,
            "is_high_pkt_count": 1 if p["pkt_count"] > 100 else 0,
            "attack_type": p["attack_type"]
        })
    return pd.DataFrame(rows)


def train(n_samples=2000):
    """Generate synthetic traffic and train the classifier"""
    print("Generating synthetic traffic from Verilog simulation...")
    packets = generate_traffic(n_samples)
    df = extract_features(packets)

    X = df.drop("attack_type", axis=1)
    y = df["attack_type"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(f"Training on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    print("\nClassification Report:")
    print(classification_report(
        y_test, clf.predict(X_test),
        target_names=[ATTACK_LABELS[i] for i in sorted(ATTACK_LABELS)]
    ))

    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")
    return clf


def load_model():
    """Load trained model or train a new one"""
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    print("No model found — training now...")
    return train()


def predict(packet):
    """Predict attack type for a single packet dict"""
    clf = load_model()
    features = pd.DataFrame([{
        "dest_port": packet["dest_port"],
        "pkt_count": packet["pkt_count"],
        "is_tcp": 1 if packet["protocol"] == "TCP" else 0,
        "is_system_port": 1 if packet["dest_port"] < 1024 else 0,
        "is_high_pkt_count": 1 if packet["pkt_count"] > 100 else 0,
    }])
    prediction = clf.predict(features)[0]
    confidence = clf.predict_proba(features).max()
    return prediction, ATTACK_LABELS[prediction], round(confidence * 100, 1)


if __name__ == "__main__":
    print("NetSentinel ML Classifier")
    print("=" * 60)
    clf = train()

    # Test on a few sample packets
    test_cases = [
        {"dest_port": 22, "pkt_count": 1, "protocol": "TCP"},
        {"dest_port": 80, "pkt_count": 150, "protocol": "TCP"},
        {"dest_port": 443, "pkt_count": 1, "protocol": "TCP"},
        {"dest_port": 8080, "pkt_count": 1, "protocol": "TCP"},
    ]

    print("\nSample Predictions:")
    print("-" * 60)
    for t in test_cases:
        attack_type, label, confidence = predict(t)
        print(f"Port {t['dest_port']:<6} pkt_count={t['pkt_count']:<4} "
              f"→ {label:<20} ({confidence}% confidence)")