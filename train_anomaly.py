import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

data = pd.read_csv("traffic_dataset.csv")

X = data.drop("label", axis=1)

model = IsolationForest(contamination=0.1)

model.fit(X)

joblib.dump(model, "anomaly_model.pkl")

print("Anomaly model trained")