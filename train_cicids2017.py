import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from flow_features import CICIDS_REQUIRED_COLUMNS, extract_from_cicids_dataframe


def load_and_preprocess(csv_path):
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path, encoding="cp1252", low_memory=False)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=CICIDS_REQUIRED_COLUMNS, inplace=True)

    print("Mapping CICIDS flow columns to shared inference features...")
    X = extract_from_cicids_dataframe(df)
    y = df["Label"]
    return X, y

def train_models(X, y):
    print(f"\nTraining on Dimensions -> {X.shape[0]} rows, {X.shape[1]} features.")
    
    print("\nTraining RandomForestClassifier for Traffic Categorization...")
    # Leveraging parallel jobs (n_jobs=-1) since this DataFrame might be massive (1,000,000+ rows)
    rf_model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    rf_model.fit(X, y)
    joblib.dump(rf_model, "traffic_model.pkl")
    print("✅ Successfully Updated -> traffic_model.pkl")
    
    print("\nTraining Unsupervised IsolationForest for Unknown Anomaly Detection...")
    iso_model = IsolationForest(contamination=0.05, n_jobs=-1, random_state=42)
    iso_model.fit(X)  # Isolation forest ignores 'y' and just finds pure statistical outliers
    joblib.dump(iso_model, "anomaly_model.pkl")
    print("✅ Successfully Updated -> anomaly_model.pkl")

if __name__ == "__main__":
    
    # Point this to whichever CSV file from the MachineLearningCVE folder you want to train on!
    TARGET_CSV = "data/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    
    if not os.path.exists(TARGET_CSV):
        print(f"❌ ERROR: Could not find {TARGET_CSV}")
        print("Please follow these instructions:")
        print("1. Download the CICIDS2017 dataset (MachineLearningCVE) from Kaggle or the UNB servers.")
        print("2. Extract the 'MachineLearningCVE' folder into your 'data/' directory.")
        print("3. Re-run this script: python train_cicids2017.py")
        exit(1)
        
    X_train, y_train = load_and_preprocess(TARGET_CSV)
    train_models(X_train, y_train)
    
    print("\n🎉 Training Complete! Your AI DPI SYSTEM is now backed by a million-packet academic dataset.")
