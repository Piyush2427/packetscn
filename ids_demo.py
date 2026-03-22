import pandas as pd
import joblib
import numpy as np

print("Loading model...")
rf_model = joblib.load('ids_random_forest_model.pkl')
le_protocol = joblib.load('protocol_encoder.pkl')

print("Model loaded!\n")
print("="*70)
print("DEMO - Test 1: Normal Traffic")
protocol_encoded = le_protocol.transform(['TCP'])[0]
features = np.array([[35650, 443, protocol_encoded, 0.443, 12, 6115, 1720, 4095, 470.0, 37.2, 3, 255, 2.27]])
pred = rf_model.predict(features)[0]
prob = rf_model.predict_proba(features)[0]
print(f"Result: {pred} ({max(prob)*100:.1f}%)")
print("="*70)
