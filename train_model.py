import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

data = pd.read_csv("traffic_dataset.csv")

X = data.drop("label", axis=1)
y = data["label"]

model = RandomForestClassifier()

model.fit(X, y)

joblib.dump(model, "traffic_model.pkl")

print("Model trained and saved")