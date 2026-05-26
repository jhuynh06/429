import numpy as np
import pandas as pd
import joblib
import shap
from model import Autoencoder, load_data

# load saved scaler and threshold
scaler = joblib.load("scaler.pkl")
threshold = np.load("threshold.npy")

# rebuild model architecture and load weights
# input_dim must match what was used during training
input_dim = scaler.n_features_in_
autoencoder = Autoencoder(input_dim=input_dim)
autoencoder.build((None, input_dim))
autoencoder.load_weights("autoencoder.weights.h5")
print(f"Loaded model (input_dim={input_dim}, threshold={threshold:.4f})")

# run on malicious repos
X_mal_scaled, mal_metadata, _, _, _ = load_data("../repos/malicious", scaler=scaler)

_, mal_errors, _ = autoencoder.predict_anomalies(X_mal_scaled, threshold=threshold)

mal_results = mal_metadata.copy()
mal_results["reconstruction_error"] = mal_errors

# per-repo anomaly detection: flag commits that deviate from their own repo's mean
# a commit is anomalous if error > repo_mean + K * repo_std
# falls back to global threshold for repos with only 1 commit
K = 2.0

def flag_per_repo(group):
    repo_median = group["reconstruction_error"].median()
    repo_mad    = (group["reconstruction_error"] - repo_median).abs().median() if len(group) > 1 else 0.0
    group["repo_median_error"] = repo_median
    group["repo_mad_error"]    = repo_mad
    group["z_score"] = (group["reconstruction_error"] - repo_median) / repo_mad if repo_mad > 0 else 0.0
    if len(group) == 1:
        group["is_anomaly"] = group["reconstruction_error"] > threshold
    else:
        group["is_anomaly"] = group["reconstruction_error"] > (repo_median + K * repo_mad)
    return group

mal_results = mal_results.groupby("source_file", group_keys=False).apply(flag_per_repo)
mal_results = mal_results.sort_values("reconstruction_error", ascending=False)
flagged_results = mal_results[mal_results["is_anomaly"]]
flagged_results.to_csv("malicious_results.csv", index=False)

flagged = mal_results["is_anomaly"].sum()
total   = len(mal_results)
print(f"Flagged {flagged} / {total} commits as anomalies (per-repo, K={K})")

# show how the known malicious commits rank
known = {
    "minimap.jsonl":                   "f26732b58c48ea63b059b458e10fbdfdaf6f8353",
    "event-stream.jsonl":              "e3163361fed01384c986b9b4c18feb1fc42b8285",
    "pacman-java_ia.jsonl":            "720890ffaf3fedff2a8caec143fbb68391c55a42",
    "SuperMario-Fr-.jsonl":            "c1d65920d268dc1d1362d8a60ae60827d67382f5",
    "KeseQul-Desktop-Alpha.jsonl":     "f3d7eb8415a3b983428a3e0f1771a5c70cad06f7",
    "BDProyecto.jsonl":                "4e536be0c1d7c0d7392960fd60ed80359ed2c474",
    "Punto-de-venta.jsonl":            "3f2073d2b1bb803c8f65ad6d5cf4a63f7c70cb30",
    "Secuencia-Numerica.jsonl":        "287ba00c931695cbbf76c28ce74a4767b06e1d0a",
    "JavaPacman.jsonl":                "6a390158526746ac79b9b05039a451fbf9012a15",
    "V2Mp3Player.jsonl":               "27d8fb491789456ee7dbfedada04fa03004e7f16",
    "RatingVoteEPITECH.jsonl":         "5b8c8acf58a14fac7fb5abc62684588fb636c8b7",
    "colors-js.jsonl":                 "074a0f8ed0c31c35d13d28632bd8a049ff136fb6",
    "ChatGPT-pdf-filler.jsonl":        "5ded617797b7db57256ae1145abc86d2599036de",
    "xz.jsonl":                        "cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0",
    "TheGreatSuspenderReloaded.jsonl": "183a5c2fe05f8c65433b066c52a44c2f48dcba61",
    "mock-interview.jsonl":            "1a21c21ddb6cf1a82aa4e2b3cefddf9c6346e1b9",
    "fastuuid.jsonl":                  "658e21039b1ecbdf7ac33219d22c1cc03270a8be",
    "ember-gen.jsonl":                 "e313caaacf8bac5a4a4866fa83260e3bcc48ff16",
    "is2-2016-1.jsonl":                "5b731630699d0143893e2faceb1e5090d6ab14bf",
    "ControldeCambios.jsonl":          "02fe964dcd1c00fc77627ea1367799883ae0e5e7",
}

print("\n{:<40} {:<8} {:<10} {:<10} {:<10}".format(
    "Repo", "Flagged", "Mal error", "Median", "MAD"))
print("-" * 80)
for source, commit in known.items():
    repo_df = mal_results[mal_results["source_file"] == source]
    if repo_df.empty:
        print("{:<40} NOT FOUND".format(source))
        continue
    mal_row = repo_df[repo_df["commit_hash"] == commit]
    flagged_str = "MISS" if mal_row.empty else ("YES" if mal_row["is_anomaly"].values[0] else "miss")
    mal_err    = mal_row["reconstruction_error"].values[0] if not mal_row.empty else float("nan")
    repo_median = repo_df["reconstruction_error"].median()
    repo_mad    = (repo_df["reconstruction_error"] - repo_median).abs().median()
    print("{:<40} {:<8} {:<10.4f} {:<10.4f} {:<10.4f}".format(
        source, flagged_str, mal_err, repo_median, repo_mad))

# SHAP explanation on flagged malicious commits
if len(flagged_results) > 0:
    # load benign data as background (representative of normal behaviour)
    X_benign, _, feat_names, _, _ = load_data("../repos/benign", scaler=scaler)
    background = X_benign[:min(100, X_benign.shape[0])]

    # get positional indices of flagged rows in X_mal_scaled
    flagged_pos = [mal_results.index.get_loc(i) for i in flagged_results.index]
    X_explain   = X_mal_scaled[flagged_pos]

    explainer   = shap.Explainer(autoencoder.rse, background, feature_names=feat_names)
    shap_values = explainer(X_explain)

    shap.summary_plot(shap_values, features=X_explain, feature_names=feat_names)

    shap_df = pd.DataFrame(shap_values.values, columns=feat_names)
    shap_df["commit_hash"]          = flagged_results["commit_hash"].values
    shap_df["author"]               = flagged_results["author"].values
    shap_df["source_file"]          = flagged_results["source_file"].values
    shap_df["reconstruction_error"] = flagged_results["reconstruction_error"].values
    shap_df["z_score"]              = flagged_results["z_score"].values
    shap_df.to_csv("shap_malicious_log.csv", index=False)
    print(f"Saved shap_malicious_log.csv ({len(flagged_results)} commits explained)")
