from collections import Counter, defaultdict
import math
import random
import statistics


LEAKAGE = {"label", "run_id", "scenario_name", "mode", "timestamp", "cpu_indexes",
           "sample_artifact", "sample_id", "sample_sha256", "family", "avclass_family",
           "architecture", "packed", "collector_git_hash", "p4_program_sha256"}
MISSING = {"", "nan", "na", "none", "null"}


def number(value):
    if value is None or str(value).strip().lower() in MISSING:
        return None
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"Nonfinite measurement: {value}")
    return parsed


def physical_issues(rows):
    issues = []
    for position, row in enumerate(rows):
        values = {}
        for name, value in row.items():
            if name.startswith(("host_", "net_")) and name not in ("host_sensor_valid", "net_sensor_valid"):
                try:
                    values[name] = number(value)
                except ValueError:
                    issues.append(f"row {position}: malformed {name}={value}")
        if any(value < 0 for value in values.values() if value is not None):
            issues.append(f"row {position}: negative count/duration")
        for total, forward, backward in (
            ("net_pkts_total_delta", "net_pkts_ab_delta", "net_pkts_ba_delta"),
            ("net_bytes_total_delta", "net_bytes_ab_delta", "net_bytes_ba_delta"),
        ):
            parts = [values.get(key) for key in (total, forward, backward)]
            if all(value is not None for value in parts) and not math.isclose(parts[0], parts[1] + parts[2]):
                issues.append(f"row {position}: forward + backward != {total}")
        minimum = values.get("net_min_len_min")
        maximum = values.get("net_max_len_max")
        packets = values.get("net_pkts_total_delta")
        byte_count = values.get("net_bytes_total_delta")
        mean = values.get("net_avg_pkt_size_delta")
        if packets and all(value is not None for value in (minimum, maximum, mean)):
            if not minimum <= mean <= maximum:
                issues.append(f"row {position}: packet size outside extrema")
        if packets and byte_count is not None:
            lower = number(row.get("min_frame_bytes"))
            upper = number(row.get("max_frame_bytes"))
            if lower is not None and byte_count < packets * lower:
                issues.append(f"row {position}: byte count below declared frame minimum")
            if upper is not None and byte_count > packets * upper:
                issues.append(f"row {position}: byte count above declared capture MTU")
        timeout = number(row.get("timeout_seconds"))
        duration = values.get("net_flow_duration_max")
        if timeout is not None and duration is not None and duration > timeout:
            issues.append(f"row {position}: flow duration exceeds observation")
    return issues


def single_label_cells(rows):
    cells = defaultdict(set)
    for row in rows:
        for names in (("mode",), ("scenario_name",), ("mode", "scenario_name")):
            if all(name in row for name in names):
                key = tuple((name, row[name]) for name in names)
                cells[key].add(row["label"])
    return {str(key): sorted(labels) for key, labels in cells.items() if len(labels) == 1}


def missing_rates(rows, columns):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["label"]].append(row)
    return {label: {name: sum(number(row.get(name)) is None for row in group) / len(group)
                    for name in columns} for label, group in grouped.items()}


def conflicting_vectors(rows, columns):
    vectors = defaultdict(set)
    for row in rows:
        vectors[tuple(number(row.get(name)) for name in columns)].add(row["label"])
    return sum(len(labels) > 1 for labels in vectors.values())


def run_matrix(rows, columns, seed, limit=2000):
    import numpy as np

    grouped = defaultdict(list)
    for row in rows:
        grouped[row["run_id"]].append(row)
    keys = sorted(grouped)
    random.Random(seed).shuffle(keys)
    keys = keys[:limit]
    matrix, labels = [], []
    for key in keys:
        group = grouped[key]
        class_labels = {row["label"] for row in group}
        if len(class_labels) != 1:
            raise ValueError(f"A4: mixed labels in run {key}; provide active-window groups")
        values = []
        for name in columns:
            observed = [number(row.get(name)) for row in group]
            present = [value for value in observed if value is not None]
            values.append(statistics.mean(present) if present else math.nan)
        matrix.append(values)
        labels.append(next(iter(class_labels)))
    if len(set(labels)) != 2:
        raise ValueError("D7/D8 require both labels")
    return np.asarray(matrix), np.asarray(labels), keys


def shortcut_diagnostics(rows, columns, seed):
    import numpy as np
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import accuracy_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.tree import DecisionTreeClassifier

    matrix, labels, keys = run_matrix(rows, columns, seed)
    if min(Counter(labels).values()) < 4:
        raise ValueError("At least four runs per label required for shortcut diagnostics")
    classes = sorted(set(labels))
    binary = np.asarray([int(label == classes[1]) for label in labels])
    train, test = train_test_split(np.arange(len(keys)), test_size=0.4, stratify=binary, random_state=seed)
    aucs = {}
    for position, name in enumerate(columns):
        if not np.isfinite(matrix[train, position]).any():
            continue
        stump = make_pipeline(SimpleImputer(strategy="median"), DecisionTreeClassifier(max_depth=1, random_state=seed))
        stump.fit(matrix[train, position:position + 1], binary[train])
        scores = stump.predict_proba(matrix[test, position:position + 1])[:, 1]
        aucs[name] = float(roc_auc_score(binary[test], scores))
    randomizer = np.random.default_rng(seed)
    accuracies, majorities = [], []
    for permutation in range(20):
        shuffled = binary.copy()
        randomizer.shuffle(shuffled)
        null_model = make_pipeline(SimpleImputer(strategy="median"), DecisionTreeClassifier(max_depth=3, random_state=seed))
        null_model.fit(matrix[train], shuffled[train])
        accuracies.append(float(accuracy_score(shuffled[test], null_model.predict(matrix[test]))))
        majorities.append(max(Counter(shuffled[test]).values()) / len(test))
    accuracy = statistics.mean(accuracies)
    majority = statistics.mean(majorities)
    tolerance = 1.96 * math.sqrt(majority * (1 - majority) / len(test))
    return {"seed": seed, "run_count": len(keys), "selected_run_ids": keys,
            "near_perfect_stumps": {name: auc for name, auc in aucs.items() if auc >= 0.98},
            "shuffled_accuracies": accuracies, "permutation_count": len(accuracies),
            "shuffled_accuracy": accuracy, "shuffled_majority": majority,
            "shuffled_95pct_threshold": min(1.0, majority + tolerance)}


def repeatability_icc(matrix):
    count = len(matrix)
    repeats = len(matrix[0])
    if count < 2 or repeats < 2 or any(len(row) != repeats for row in matrix):
        raise ValueError("ICC requires a rectangular repeated-measures matrix")
    means = [statistics.mean(row) for row in matrix]
    grand = statistics.mean(means)
    between = repeats * sum((value - grand) ** 2 for value in means) / (count - 1)
    within = sum((value - mean) ** 2 for row, mean in zip(matrix, means)
                 for value in row) / (count * (repeats - 1))
    denominator = between + (repeats - 1) * within
    return (between - within) / denominator if denominator else None


def zero_failure_upper_bound(comparisons):
    if comparisons < 1:
        raise ValueError("No clean comparisons, no confidence bound")
    return 1 - 0.05 ** (1 / comparisons)


def stratified_schedule(records, seed, per_class=30):
    if not 1 <= per_class <= 30:
        raise ValueError("Hard limit: at most 30 unique samples per class")
    randomizer = random.Random(seed)
    selected = {}
    for label in ("malware", "benign"):
        strata = defaultdict(list)
        for record in records:
            if record["label"] != label:
                continue
            names = ("avclass_family", "architecture", "packed") if label == "malware" else ("workload_kind",)
            key = tuple(record[name] for name in names)
            strata[key].append(record)
        buckets = list(strata.values())
        randomizer.shuffle(buckets)
        for bucket in buckets:
            randomizer.shuffle(bucket)
        chosen = []
        while buckets and len(chosen) < per_class:
            for bucket in list(buckets):
                chosen.append(bucket.pop())
                if not bucket:
                    buckets.remove(bucket)
                if len(chosen) == per_class:
                    break
        selected[label] = chosen
    schedule = []
    while any(selected.values()):
        order = list(selected)
        randomizer.shuffle(order)
        schedule.extend(selected[label].pop() for label in order if selected[label])
    return {"seed": seed, "records": schedule}