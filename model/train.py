import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle

def load_data(filepath):
    df = pd.read_csv(filepath)
    return df

def train_model(df):
    feature_cols = [col for col in df.columns if col not in ['url', 'status']]
    X = df[feature_cols].values
    y = df['status']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print(classification_report(y_test, y_pred))

    with open('model/phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("✅ Model saved!")

if __name__ == "__main__":
    df = load_data('model/dataset.csv')
    train_model(df)