import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers
from tensorflow.keras.models import Model
from pathlib import Path
from sklearn.preprocessing import StandardScaler

# Baseline for autoencoder: https://www.tensorflow.org/tutorials/generative/autoencoder
# SHAP documentation: https://shap.readthedocs.io/en/latest/

class Autoencoder(Model):

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

    def call(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def train(self, X_train, X_val=None, epochs=50, batch_size=32, patience=5):
        self.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3), loss='mae')
        validation_data = (X_val, X_val) if X_val is not None else None
        monitor = 'val_loss' if validation_data is not None else 'loss'
        callbacks = [
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor=monitor,
                factor=0.5,
                patience=5,
                min_lr=1e-5,
                verbose=1,
            ),
            tf.keras.callbacks.EarlyStopping(
                monitor=monitor,
                patience=patience,
                restore_best_weights=True,
                verbose=1,
            ),
        ]
        history = self.fit(
            X_train, X_train,
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            validation_data=validation_data,
            callbacks=callbacks,
        )
        return history

    # get reconstruction error
    def rse(self, X):
        reconstructed = self.predict(X)
        errors = np.mean(np.abs(X - reconstructed), axis=1)
        return errors

    # predict anomalies by comparing reconstruction error to threshold
    def predict_anomalies(self, X, threshold=None):
        errors = self.rse(X)
        if threshold is None:
            threshold = np.percentile(errors, 99)
        anomalies = errors > threshold
        return anomalies, errors, threshold


# 23 features from Repos
def load_data(data_folder, scaler=None):
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

    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_df)  # fit + transform for benign training data
    else:
        X_scaled = scaler.transform(X_df)       # transform only, preserves benign scale

    return X_scaled, metadata, feature_names, scaler, combined_df
