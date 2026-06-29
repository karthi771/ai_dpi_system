import joblib
import pandas as pd
from pathlib import Path

from flow_features import features_to_model_frame


class AIClassifier:

    def __init__(self):
        model_path = Path("traffic_model_multiclass.pkl")
        if not model_path.exists():
            model_path = Path("traffic_model.pkl")

        self.model = joblib.load(model_path)

        # Force single-threaded inference when running inside background threads.
        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1

    def predict(self, features, flow_key=None):
        df = features_to_model_frame(features)
        prediction = self.model.predict(df)
        return prediction[0]
