# SHAP Analysis — Malicious Repos

## Flagged Commits & Top Features per Repo

| Repo | Flagged | #1 Feature | #2 Feature | #3 Feature |
|---|---|---|---|---|
| BDProyecto | 1 | author_days_active | author_file_type_novelty | seconds_since_author_last_commit |
| ChatGPT-pdf-filler | 1 | author_days_active | msg_entropy | pct_config_files_touched |
| ControldeCambios | 33 | author_days_active | pct_config_files_touched | dmm_unit_complexity |
| JavaPacman | 4 | author_days_active | seconds_since_author_last_commit | dmm_unit_complexity |
| KeseQul-Desktop-Alpha | 11 | author_days_active | msg_entropy | dmm_unit_complexity |
| Punto-de-venta | 1 | author_days_active | author_file_type_novelty | seconds_since_author_last_commit |
| RatingVoteEPITECH | 1 | author_days_active | dmm_unit_complexity | msg_entropy |
| SuperMario-Fr- | 21 | author_days_active | pct_config_files_touched | dmm_unit_complexity |
| TheGreatSuspenderReloaded | 6 | author_days_active | dmm_unit_complexity | seconds_since_author_last_commit |
| V2Mp3Player | 2 | author_days_active | msg_entropy | pct_config_files_touched |
| colors-js | 82 | author_days_active | dmm_unit_complexity | seconds_since_author_last_commit |
| ember-gen | 32 | author_days_active | pct_config_files_touched | seconds_since_author_last_commit |
| event-stream | 61 | author_days_active | seconds_since_author_last_commit | dmm_unit_complexity |
| fastuuid | 37 | author_days_active | dmm_unit_complexity | seconds_since_author_last_commit |
| is2-2016-1 | 5 | author_days_active | dmm_unit_complexity | seconds_since_author_last_commit |
| minimap | 512 | author_days_active | seconds_since_author_last_commit | dmm_unit_complexity |
| mock-interview | 4 | author_days_active | pct_config_files_touched | seconds_since_author_last_commit |
| pacman-java_ia | 21 | author_days_active | total_deletions | pct_config_files_touched |
| xz | 56 | author_days_active | seconds_since_author_last_commit | pct_config_files_touched |

**Total flagged: 900 commits across 19 repos**

## Key Findings

- `author_days_active` is the #1 driver in every single repo — by a large margin
- Secondary features (`dmm_unit_complexity`, `seconds_since_author_last_commit`, `pct_config_files_touched`) are plausibly security-relevant but contribute minimally relative to #1
- This points to a **selection bias**: benign training set consists of large, established projects (Linux, Kubernetes, React, curl, etc.) with long-tenured contributors; malicious repos tend to be small projects with newer authors
- The model learned "short author history = anomalous" rather than purely detecting malicious behavior

## Known Misses (known malicious commit not flagged)

| Repo | Reason |
|---|---|
| xz | Malicious commit scores *below* repo median — attack engineered to look normal over 2+ years |
| event-stream | Malicious commit scores below repo median — new maintainer attack blended in |
| Secuencia-Numerica | Small repo, commit close to threshold |
| V2Mp3Player | Small repo, low reconstruction error |
| RatingVoteEPITECH | Small repo, commit close to threshold |
| ChatGPT-pdf-filler | Small repo, mid-pack error |
| fastuuid | Commit within K=2 MAD band |
| ember-gen | Commit within K=2 MAD band |
