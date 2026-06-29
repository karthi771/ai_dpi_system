import joblib
import warnings

from flow_features import features_to_model_frame

warnings.filterwarnings("ignore", category=UserWarning)


class AnomalyDetector:

    def __init__(self):
        try:
            self.model = joblib.load("anomaly_model.pkl")
            if hasattr(self.model, "n_jobs"):
                self.model.n_jobs = 1
        except FileNotFoundError:
            self.model = None

    def detect(self, features):
        if not self.model:
            if features["packet_count"] > 50:
                return "Possible DDoS"
            if features["avg_packet_size"] < 60 and features["packet_count"] > 20:
                return "Possible Port Scan"
            return None

        df = features_to_model_frame(features)
        prediction = self.model.predict(df)[0]
        if prediction == -1:
            return "Statistical Anomaly Detected (IsolationForest)"
        return None
