# 429 Project

**CSC 429 - Current Topics in Cybersecurity, Cal Poly San Luis Obispo**

**Instructor: Dongfeng Fang**

**Team Members:**

- Jason Huynh
- Tristan Au
- Vincent Wu Zhang
- Abdullah Tanveer

## Feature Extraction

Each dataset was obtained through our own data processing pipeline. All data is exported into a singler json file for the specified repository. **Pydriller** was used to mine commit metadata throughout, and we took all of the commit data and made the following features for our dataset:

| Feature | Description |
|---------|-------------|
| `commit_hash` | Unique commit identifier |
| `author` | Commit author |
| `hour_of_day` | Hour the commit was made (0-23) |
| `day_of_week` | Day of the week |
| `seconds_since_author_last_commit` | Time gap between consecutive commits |
| `num_files` | Number of files changed |
| `total_insertions` | Lines added |
| `total_deletions` | Lines removed |
| `ins_del_ratio` | Ratio of insertions to deletions |
| `num_adds` | New files added |
| `num_deletes` | Files deleted |
| `num_renames` | Files renamed |
| `pct_config_files_touched` | % of changed files that are config files |
| `avg_file_complexity` | Average complexity across changed files |
| `max_file_complexity` | Max complexity among changed files |
| `msg_length` | Commit message length |
| `msg_entropy` | Shannon entropy of commit message |
| `author_total_prior_commits` | Author's cumulative commit count |
| `author_days_active` | Days since author's first commit |
| `author_file_type_novelty` | Whether author touched new file types |
| `timezone_shift_from_author_norm` | Deviation from author's usual timezone |
| `dmm_unit_size` | Delta Maintainability Model – unit size |
| `dmm_unit_complexity` | Delta Maintainability Model – complexity |

Installation for dependencies:
```
pip install pydriller
```

Running the actual pipeline takes this format:
```
python pipeline.py REPO_URL OUTPUT.jsonl
```
The output path must end in `.jsonl`. The file (and any missing parent directories) will be created if it does not already exist.
