import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
import tensorflow as tf
from sklearn.model_selection import train_test_split
from tensorflow.keras import layers, losses
from tensorflow.keras.models import Model

# Baseline for autoencoder: https://www.tensorflow.org/tutorials/generative/autoencoder
# SHAP documentation: https://shap.readthedocs.io/en/latest/


class Autoencoder(Model):
    # follow Anomaly detector example on pag

    # how do we initalize this?
    def __init__(self, input_dim, encoding_dim=16):
        pass

    # build the various layers of the autoencoder
    def _build(self):
        pass

    # train the model (what parameters?)
    def train(self, X_train, epochs=50, batch_size=32):
        pass

    # get reconstruction error
    def rse(self, X):
        pass

    # how do we predict anomalies? (i.e we get some sort of RSE and compare to our threshold)
    def predict_anomalies(self, X, threshold=None):
        pass


# figure out how to load data from our various json files
def load_data():
    pass


# run autoencoder

# run SHAP

# export SHAP log
