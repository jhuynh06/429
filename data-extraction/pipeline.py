import argparse
import json
import math
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timezone #Needed for Benign
from dateutil.relativedelta import relativedelta #Needed for Benign

from pydriller import Repository

CONFIG_PATH_SUBSTRINGS = (".github/workflows/",)
CONFIG_FILENAMES = {
    "dockerfile",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
}
CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".ini", ".cfg"}

FEATURE_COLUMNS = [
    "commit_hash",
    "author",
    "hour_of_day",
    "day_of_week",
    "seconds_since_author_last_commit",
    "num_files",
    "total_insertions",
    "total_deletions",
    "ins_del_ratio",
    "num_adds",
    "num_deletes",
    "num_renames",
    "pct_config_files_touched",
    "avg_file_complexity",
    "max_file_complexity",
    "msg_length",
    "msg_entropy",
    "author_total_prior_commits",
    "author_days_active",
    "author_file_type_novelty",
    "timezone_shift_from_author_norm",
    "dmm_unit_size",
    "dmm_unit_complexity",
]


def jsonl_path(value):
    path = Path(value)
    if path.suffix.lower() != ".jsonl":
        raise argparse.ArgumentTypeError(
            f"output file must have a .jsonl extension (got {value!r})"
        )
    return path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract data from a repository.",
    )
    parser.add_argument(
        "repo_url",
        help="URL of the repository to process.",
    )
    parser.add_argument(
        "output",
        type=jsonl_path,
        help="Path to output .jsonl file (created if it does not exist).",
    )
    return parser.parse_args()


def file_extension(path):
    if not path:
        return ""
    name = path.rsplit("/", 1)[-1].lower()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def is_config_file(path):
    if not path:
        return False
    lower = path.lower()
    if any(s in lower for s in CONFIG_PATH_SUBSTRINGS):
        return True
    name = lower.rsplit("/", 1)[-1]
    if name in CONFIG_FILENAMES:
        return True
    return file_extension(lower) in CONFIG_EXTENSIONS


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def timezone_offset_hours(tz_seconds):
    if tz_seconds is None:
        return 0.0
    return -tz_seconds / 3600.0


def new_author_state():
    return {
        "commit_count": 0,
        "first_commit_ts": None,
        "last_commit_ts": None,
        "extensions_seen": set(),
        "timezone_counter": Counter(),
        "timezone_mode_hours": None,
    }


def featurize_commit(commit, author_state):
    author_key = commit.author.email or commit.author.name or "unknown"
    state = author_state[author_key]

    author_date = commit.author_date

    if state["last_commit_ts"] is not None:
        seconds_since_author_last_commit = (
            author_date - state["last_commit_ts"]
        ).total_seconds()
    else:
        seconds_since_author_last_commit = -1.0

    mods = list(commit.modified_files)
    num_files = len(mods)
    total_insertions = sum((m.added_lines or 0) for m in mods)
    total_deletions = sum((m.deleted_lines or 0) for m in mods)
    ins_del_ratio = (
        total_insertions / total_deletions
        if total_deletions > 0
        else float(total_insertions)
    )

    num_adds = sum(1 for m in mods if getattr(m.change_type, "name", "") == "ADD")
    num_deletes = sum(1 for m in mods if getattr(m.change_type, "name", "") == "DELETE")
    num_renames = sum(1 for m in mods if getattr(m.change_type, "name", "") == "RENAME")

    config_touched = sum(
        1 for m in mods if is_config_file(m.new_path) or is_config_file(m.old_path)
    )
    pct_config_files_touched = (config_touched / num_files) if num_files else 0.0

    complexities = [m.complexity for m in mods if m.complexity is not None]
    avg_file_complexity = sum(complexities) / len(complexities) if complexities else 0.0
    max_file_complexity = max(complexities) if complexities else 0.0

    msg = commit.msg or ""
    msg_length = len(msg)
    msg_entropy = shannon_entropy(msg)

    author_total_prior_commits = state["commit_count"]
    if state["first_commit_ts"] is not None:
        author_days_active = (
            author_date - state["first_commit_ts"]
        ).total_seconds() / 86400.0
    else:
        author_days_active = 0.0

    extensions_in_commit = {
        file_extension(m.new_path or m.old_path or "") for m in mods
    }
    extensions_in_commit.discard("")
    if extensions_in_commit:
        novel = extensions_in_commit - state["extensions_seen"]
        author_file_type_novelty = len(novel) / len(extensions_in_commit)
    else:
        author_file_type_novelty = 0.0

    tz_hours = timezone_offset_hours(commit.author_timezone)
    if state["timezone_mode_hours"] is not None:
        timezone_shift_from_author_norm = abs(tz_hours - state["timezone_mode_hours"])
    else:
        timezone_shift_from_author_norm = 0.0

    dmm_unit_size = commit.dmm_unit_size if commit.dmm_unit_size is not None else 0.0
    dmm_unit_complexity = (
        commit.dmm_unit_complexity if commit.dmm_unit_complexity is not None else 0.0
    )

    features = {
        "commit_hash": commit.hash,
        "author": author_key,
        "hour_of_day": author_date.hour,
        "day_of_week": author_date.weekday(),
        "seconds_since_author_last_commit": seconds_since_author_last_commit,
        "num_files": num_files,
        "total_insertions": total_insertions,
        "total_deletions": total_deletions,
        "ins_del_ratio": ins_del_ratio,
        "num_adds": num_adds,
        "num_deletes": num_deletes,
        "num_renames": num_renames,
        "pct_config_files_touched": pct_config_files_touched,
        "avg_file_complexity": avg_file_complexity,
        "max_file_complexity": max_file_complexity,
        "msg_length": msg_length,
        "msg_entropy": msg_entropy,
        "author_total_prior_commits": author_total_prior_commits,
        "author_days_active": author_days_active,
        "author_file_type_novelty": author_file_type_novelty,
        "timezone_shift_from_author_norm": timezone_shift_from_author_norm,
        "dmm_unit_size": dmm_unit_size,
        "dmm_unit_complexity": dmm_unit_complexity,
    }

    state["commit_count"] += 1
    state["last_commit_ts"] = author_date
    if state["first_commit_ts"] is None:
        state["first_commit_ts"] = author_date
    state["extensions_seen"].update(extensions_in_commit)
    state["timezone_counter"][tz_hours] += 1
    state["timezone_mode_hours"] = state["timezone_counter"].most_common(1)[0][0]

    return features


def extract_metadata(repo_url):
    author_state = defaultdict(new_author_state)
    for commit in Repository(repo_url).traverse_commits():
        yield featurize_commit(commit, author_state)

# def extract_metadata(repo_url): #Used this one for benign repos
#     author_state = defaultdict(new_author_state)

#     since_date = datetime.now(timezone.utc) - relativedelta(months=2)

#     for commit in Repository(repo_url, since=since_date).traverse_commits():
#         yield featurize_commit(commit, author_state)

if __name__ == "__main__":
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    print(f"pipeline mining {args.repo_url} -> {args.output}", file=sys.stderr)
    start = time.time()
    count = 0
    with args.output.open("w", encoding="utf-8") as f:
        for row in extract_metadata(args.repo_url):
            f.write(json.dumps(row) + "\n")
            count += 1
            if count % 25 == 0:
                elapsed = time.time() - start
                print(
                    f"\rpipeline processed {count} commits ({count / elapsed:.1f}/s)",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
    elapsed = time.time() - start
    print(
        f"\rpipeline done: {count} commits in {elapsed:.1f}s -> {args.output}",
        file=sys.stderr,
    )
