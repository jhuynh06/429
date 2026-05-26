import numpy as np
import pandas as pd
import joblib
import shap
from sklearn.model_selection import train_test_split
from model import Autoencoder, load_data

# load and scale benign training data
X_scaled, metadata, feature_names, scaler, combined_df = load_data("../repos/benign")

X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)

# train autoencoder
input_dim = X_train.shape[1]
autoencoder = Autoencoder(input_dim=input_dim)
history = autoencoder.train(X_train, X_val=X_test, epochs=200, patience=10)

# compute threshold from benign training errors
train_errors = autoencoder.rse(X_train)
threshold = np.percentile(train_errors, 99)

# save model weights, scaler, and threshold
autoencoder.save_weights("autoencoder.weights.h5")
joblib.dump(scaler, "scaler.pkl")
np.save("threshold.npy", threshold)
print(f"Saved weights, scaler, and threshold (threshold={threshold:.4f})")

# sanity check on benign data
all_anomalies, all_errors, _ = autoencoder.predict_anomalies(X_scaled, threshold=threshold)
results = metadata.copy()
results["reconstruction_error"] = all_errors
results["is_anomaly"] = all_anomalies
results = results.sort_values("reconstruction_error", ascending=False)
results.to_csv("anomaly_results.csv", index=False)
print(f"Benign set: flagged {all_anomalies.sum()} / {len(all_anomalies)} as anomalies")

# SHAP explanation on top anomalies
background = X_train[:min(100, X_train.shape[0])]

anomaly_indices = np.where(all_anomalies)[0]
anomaly_indices = anomaly_indices[np.argsort(all_errors[anomaly_indices])[::-1]]

if len(anomaly_indices) > 0:
    explained_indices = anomaly_indices[:min(50, len(anomaly_indices))]
    X_explain = X_scaled[explained_indices]

    explainer = shap.Explainer(autoencoder.rse, background, feature_names=feature_names)
    shap_values = explainer(X_explain)

    shap.summary_plot(shap_values, features=X_explain, feature_names=feature_names)

    shap_df = pd.DataFrame(shap_values.values, columns=feature_names)
    shap_df["commit_hash"]          = metadata.iloc[explained_indices]["commit_hash"].values
    shap_df["author"]               = metadata.iloc[explained_indices]["author"].values
    shap_df["source_file"]          = metadata.iloc[explained_indices]["source_file"].values
    shap_df["reconstruction_error"] = all_errors[explained_indices]
    shap_df["is_anomaly"]           = all_anomalies[explained_indices]
    shap_df.to_csv("shap_anomaly_log.csv", index=False)
    print(f"Saved shap_anomaly_log.csv ({len(explained_indices)} anomalies explained)")
else:
    print("No anomalies found in benign set — skipping SHAP")
