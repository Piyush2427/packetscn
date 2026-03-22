import pandas as pd
import joblib
import numpy as np

class IDSPredictor:
    def __init__(self):
        self.rf_model = joblib.load('ids_random_forest_model.pkl')
        self.le_protocol = joblib.load('protocol_encoder.pkl')
        self.feature_columns = joblib.load('feature_columns.pkl')

    def predict_realtime(self, src_port, dst_port, protocol, duration_sec, packet_count, 
                        total_bytes, src_bytes, dst_bytes, avg_pkt_size, packets_per_sec, 
                        flags_count, ttl, payload_entropy):
        protocol_encoded = self.le_protocol.transform([protocol])[0]
        features = np.array([[src_port, dst_port, protocol_encoded, duration_sec, packet_count, 
                             total_bytes, src_bytes, dst_bytes, avg_pkt_size, packets_per_sec, 
                             flags_count, ttl, payload_entropy]])
        prediction = self.rf_model.predict(features)[0]
        probability = self.rf_model.predict_proba(features)[0]
        return {'prediction': prediction, 'confidence': max(probability) * 100}
