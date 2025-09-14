import time
import json
from datetime import datetime
from io import StringIO
from typing import List, Dict, Optional

import pandas as pd

# -------------------------------------------------------------------
# In-memory stores for demo session
# -------------------------------------------------------------------
_file_metrics: List[Dict]     = []
_text_metrics: List[Dict]     = []
_accuracy_results: List[Dict] = []

# -------------------------------------------------------------------
# Recording functions
# -------------------------------------------------------------------
def record_file_metrics(
    file_name: str,
    start_ts: float,
    end_ts: float,
    pii_count: int,
    record_count: int,
    audit_gen_ts: Optional[float] = None,
    raw_file_bytes: Optional[bytes] = None,
    audit_csv: Optional[str] = None,
) -> None:
    """
    Capture metrics for a multi-record file and, if it’s ground_truth,
    also compute precision/recall/F1.
    """
    latency = end_ts - start_ts
    audit_latency = (audit_gen_ts - start_ts) if audit_gen_ts else None
    pii_density = pii_count / record_count if record_count else 0.0

    _file_metrics.append({
        "timestamp":      datetime.utcnow().isoformat(),
        "file_name":      file_name,
        "records":        record_count,
        "pii_count":      pii_count,
        "pii_density":    pii_density,
        "latency_sec":    latency,
        "audit_time_sec": audit_latency
    })

    # if this is a ground_truth file, trigger accuracy computation
    if file_name.startswith("ground_truth") and raw_file_bytes and audit_csv:
        _compute_accuracy(file_name, raw_file_bytes, audit_csv)

def record_text_metrics(
    start_ts: float,
    end_ts: float,
    pii_count: int,
    audit_gen_ts: Optional[float] = None,
) -> None:
    latency = end_ts - start_ts
    audit_latency = (audit_gen_ts - start_ts) if audit_gen_ts else None

    _text_metrics.append({
        "timestamp":      datetime.utcnow().isoformat(),
        "pii_count":      pii_count,
        "latency_sec":    latency,
        "audit_time_sec": audit_latency
    })

# -------------------------------------------------------------------
# Accuracy computation for ground_truth
# -------------------------------------------------------------------
def _compute_accuracy(
    file_name: str,
    raw_json_bytes: bytes,
    audit_csv: str
) -> None:
    """
    Loads the ground_truth.json payload, compares audit_csv predictions
    to the injected spans, then records TP/FP/FN, precision, recall, F1.
    """
    data = json.loads(raw_json_bytes.decode("utf-8"))
    df_audit = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()

    TP = FP = FN = 0
    for rec in data:
        vid = rec["verbatim_id"]
        # build ground truth set of (type, value)
        gt = set((e["type"], e["value"]) for e in rec["ground_truth"])
        # build predicted set of (pii_type, original)
        preds = df_audit[df_audit["verbatim_id"] == vid]
        pr = set(zip(preds["pii_type"].str.upper(), preds["original"]))

        TP += len(gt & pr)
        FP += len(pr - gt)
        FN += len(gt - pr)

    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall    = TP / (TP + FN) if (TP + FN) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    _accuracy_results.append({
        "timestamp": datetime.utcnow().isoformat(),
        "file_name": file_name,
        "TP":         TP,
        "FP":         FP,
        "FN":         FN,
        "precision":  precision,
        "recall":     recall,
        "f1":         f1
    })

# -------------------------------------------------------------------
# Retrieval functions
# -------------------------------------------------------------------
def get_file_metrics_df() -> pd.DataFrame:
    return pd.DataFrame(_file_metrics)

def get_text_metrics_df() -> pd.DataFrame:
    return pd.DataFrame(_text_metrics)

def get_accuracy_df() -> pd.DataFrame:
    return pd.DataFrame(_accuracy_results)

# -------------------------------------------------------------------
# Summary functions
# -------------------------------------------------------------------
def summarize_file_metrics() -> Dict:
    df = get_file_metrics_df()
    if df.empty:
        return {}
    total_records = df["records"].sum()
    total_pii     = df["pii_count"].sum()
    return {
        "files_processed":     len(df),
        "avg_latency_sec":     df["latency_sec"].mean(),
        "max_latency_sec":     df["latency_sec"].max(),
        "avg_pii_density":     df["pii_density"].mean(),
        "avg_pii_per_record":  total_pii / total_records if total_records else 0
    }

def summarize_text_metrics() -> Dict:
    df = get_text_metrics_df()
    if df.empty:
        return {}
    total_pii = df["pii_count"].sum()
    return {
        "texts_processed":     len(df),
        "avg_latency_sec":     df["latency_sec"].mean(),
        "max_latency_sec":     df["latency_sec"].max(),
        "avg_pii_per_text":    total_pii / len(df) if len(df) else 0
    }

def summarize_accuracy() -> Dict:
    df = get_accuracy_df()
    if df.empty:
        return {}
    latest = df.iloc[-1]
    return {
        "precision": latest["precision"],
        "recall":    latest["recall"],
        "f1_score":  latest["f1"]
    }
