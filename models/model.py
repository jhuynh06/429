import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
import tensorflow as tf
from sklearn.model_selection import train_test_split
from tensorflow.keras import layers, losses
from tensorflow.keras.models import Model
from pathlib import Path
from sklearn.preprocessing import StandardScaler

# Baseline for autoencoder: https://www.tensorflow.org/tutorials/generative/autoencoder
# SHAP documentation: https://shap.readthedocs.io/en/latest/

class Autoencoder(Model):
    # follow Anomaly detector example on pag

    # how do we initalize this?
    def __init__(self, input_dim, encoding_dim=16):
        super(Autoencoder, self).__init__()
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim

        self.encoder = tf.keras.Sequential([
            layers.Dense(encoding_dim, activation='relu'),
        ])

        self.decoder = tf.keras.Sequential([
            layers.Dense(input_dim, activation='linear')
        ])

    # build the various layers of the autoencoder
    def call(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    # train the model (what parameters?)
    def train(self, X_train, epochs=50, batch_size=32):
        self.compile(optimizer='adam', loss='mae')
        history = self.fit(X_train, X_train, epochs=epochs, batch_size=batch_size, shuffle=True)
        return history

    # get reconstruction error
    def rse(self, X):
        reconstructed = self.predict(X)
        errors = np.mean(np.abs(X - reconstructed), axis = 1)
        return errors       

    # how do we predict anomalies? (i.e we get some sort of RSE and compare to our threshold)
    def predict_anomalies(self, X, threshold=None):
        errors = self.rse(X)
        if threshold is None:
            threshold = np.percentile(errors, 99) #This would be the default threshold if threshold is none

        anomalities = errors > threshold
        return anomalities, errors, threshold


#23 features from Repos
# figure out how to load data from our various json files
def load_data(data_folder):
    datapath = Path(data_folder)
    print("Looking for files in:", datapath.resolve())
    jsonl_files = list(datapath.glob("*.jsonl"))

    dfs = []

    for file in jsonl_files:
        df = pd.read_json(file, lines=True)
        df['source_file'] = file.name
        dfs.append(df)
    
    combined_df = pd.concat(dfs, ignore_index=True)

    metadata_cols = ["commit_hash", "author", "source_file"]
    metadata_cols = [col for col in metadata_cols if col in combined_df.columns]
    metadata = combined_df[metadata_cols].copy()

    X_df = combined_df.drop(columns=metadata_cols, errors="ignore")
    feature_names = X_df.columns.tolist()

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_df)
    
    return X_scaled, metadata, feature_names, scaler, combined_df

# run autoencoder
X_scaled, metadata, feature_names, scaler, combined_df = load_data("../repos/benign")

X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)

input_dim = X_train.shape[1] #gets the amount of features from the dataset
autoencoder = Autoencoder(input_dim=input_dim)

history = autoencoder.train(X_train)
train_errors = autoencoder.rse(X_train)

threshold = np.percentile(train_errors, 99)

all_anomalies, all_errors, threshold = autoencoder.predict_anomalies(
    X_scaled,
    threshold = threshold
)

results = metadata.copy()
results["reconstruction_error"] = all_errors
results["is_anomaly"] = all_anomalies

results = results.sort_values("reconstruction_error", ascending=False)
results.to_csv("anomaly_results.csv", index=False)

# run SHAP
def anomaly_score_predict(x):
    reconstructed = autoencoder.predict(x)
    return np.mean(np.abs(x - reconstructed), axis=1)

background_data = shap.sample(X_train, 100)
explainer = shap.KernelExplainer(anomaly_score_predict, background_data)

#Currently only does the Top 20 anomalies, can do more but takes more computational power
top_anomaly_indices = results.head(20).index
X_to_explain = X_scaled[top_anomaly_indices]

print(f"Calculating SHAP values for top {len(X_to_explain)} anomalies: ")
shap_values = explainer.shap_values(X_to_explain)

print("SHAP summary plot: ")
shap.summary_plot(shap_values, X_to_explain, feature_names=feature_names)

#export SHAP
shap_df = pd.DataFrame(shap_values, columns=feature_names)
shap_df['original_index'] = top_anomaly_indices
shap_df.to_csv("shap_anomaly_explanations.csv", index=False)
print("SHAP values exported to shap_anomaly_explanations.csv")