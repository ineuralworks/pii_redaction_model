import time
import json
from datetime import datetime
from io import StringIO
from typing import List, Dict, Optional
import re
import pandas as pd

# -------------------------------------------------------------------
# In-memory stores for demo session
# -------------------------------------------------------------------
_file_metrics: List[Dict]         = []
_text_metrics: List[Dict]         = []
_accuracy_results: List[Dict]     = []
_ground_truth_reports: Dict[str, str] = {}

# -------------------------------------------------------------------
# Canonical PII type mapping (all aliases → one canonical)
# -------------------------------------------------------------------
PII_CANONICAL = {
    # DOB variations
    "DOB":             "DOB",
    "DATE_OF_BIRTH":   "DOB",
    "BIRTH_DATE":      "DOB",
    
    # Email variations
    "EMAIL":           "EMAIL",
    "EMAIL_ADDRESS":   "EMAIL",
    # Phone variations
    "PHONE":           "PHONE",
    "PHONE_NUMBER":    "PHONE",
    # SSN variations
    "SSN":             "SSN",
}

def _canonical(t: str) -> str:
    """Map any PII label to its canonical form."""
    return PII_CANONICAL.get(t.upper(), t.upper())

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
        report_csv = _generate_ground_truth_report(raw_file_bytes, audit_csv)
        _ground_truth_reports[file_name] = report_csv

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


# regex to remove honorifics from GT names only
HONORIFIC_RE = re.compile(r'\b(?:Mr|Mrs|Ms|Dr)\.\s*', re.IGNORECASE)
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

        # 1) Build ground-truth set, normalizing NAMEs
        gt = set()
        for e in rec["ground_truth"]:
            t = _canonical(e["type"])
            v = e["value"]
            if t == "NAME":
                # drop Mr./Mrs./Ms./Dr. before compare
                v = HONORIFIC_RE.sub('', v).strip()
            gt.add((t, v))

        # 2) canonicalize prediction types
        preds = df_audit[df_audit["verbatim_id"] == vid]
        pr = set(zip(preds["pii_type"].apply(_canonical),preds["original"]))

        # 3) Strict intersection for TP/FP/FN
        TP += len(gt & pr)
        FP += len(pr - gt)
        FN += len(gt - pr)
    # for rec in data:
    #     vid = rec["verbatim_id"]

    #     # canonicalize ground-truth types
    #     gt = set((
    #         _canonical(e["type"]),
    #         e["value"]
    #     ) for e in rec["ground_truth"])

    #     # canonicalize prediction types
    #     preds = df_audit[df_audit["verbatim_id"] == vid]
    #     pr = set(zip(
    #         preds["pii_type"].apply(_canonical),
    #         preds["original"]
    #     ))

    #     TP += len(gt & pr)
    #     FP += len(pr - gt)
    #     FN += len(gt - pr)

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
# Ground-truth report generation (correct vs missed)
# -------------------------------------------------------------------
def _generate_ground_truth_report(
    raw_json_bytes: bytes,
    audit_csv: str
) -> str:
    data = json.loads(raw_json_bytes.decode("utf-8"))
    df_audit = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()

    rows = []
    for rec in data:
        vid = rec["verbatim_id"]
        preds = df_audit[df_audit["verbatim_id"] == vid]
        pred_set = set(zip(
            preds["pii_type"].apply(_canonical),
            preds["original"]
        ))

        for ent in rec["ground_truth"]:
            gt_type  = _canonical(ent["type"])
            gt_value = ent["value"]
            status   = "correct" if (gt_type, gt_value) in pred_set else "missed"
            rows.append({
                "verbatim_id":         vid,
                "ground_truth_type":   gt_type,
                "ground_truth_value":  gt_value,
                "status":              status,
            })

    df_report = pd.DataFrame(rows)
    return df_report.to_csv(index=False)

# -------------------------------------------------------------------
# Retrieval functions
# -------------------------------------------------------------------
def get_file_metrics_df() -> pd.DataFrame:
    return pd.DataFrame(_file_metrics)

def get_text_metrics_df() -> pd.DataFrame:
    return pd.DataFrame(_text_metrics)

def get_accuracy_df() -> pd.DataFrame:
    return pd.DataFrame(_accuracy_results)

def get_ground_truth_report(file_name: str) -> Optional[str]:
    return _ground_truth_reports.get(file_name)

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

# -------------------------------------------------------------------
# New: Business‐Friendly Summary under metrics
# -------------------------------------------------------------------
def generate_business_summary(file_name: str) -> Optional[str]:
    """
    Combines file‐ and accuracy‐metrics, then returns a
    non-technical, conversational summary for this file.
    """
    df_file = get_file_metrics_df()
    df_acc  = get_accuracy_df()

    fm = df_file[df_file["file_name"] == file_name]
    am = df_acc[df_acc["file_name"] == file_name]
    if fm.empty or am.empty:
        return None

    latest_file = fm.sort_values("timestamp").iloc[-1]
    latest_acc  = am.sort_values("timestamp").iloc[-1]

    latency   = latest_file["latency_sec"]
    density   = latest_file["pii_density"]
    prec_pct  = latest_acc["precision"] * 100
    rec_pct   = latest_acc["recall"]    * 100
    f1_pct    = latest_acc["f1"]        * 100

    lines = [
        "# 📝 Automatic Redaction Summary",
        "## 1. Speed & Volume",
        f"We processed **{file_name}** in **{latency:.1f}s**, masking on average **{density:.1f}** sensitive items per record.",
        "## 2. Performance at a Glance",
        f"- When the system redacted data, it was correct **{prec_pct:.1f}%** of the time (only {100-prec_pct:.1f}% were unnecessary masks).",
        f"- It identified **{rec_pct:.1f}%** of all sensitive items (just {100-rec_pct:.1f}% went unnoticed).",
        f"- Overall effectiveness sits at **{f1_pct:.1f}%**.",
        "## 3. Business Implications"
    ]

    if prec_pct >= 98 and rec_pct >= 98:
        impact = (
            "Exceptional results: both missed data and false alarms "
            "are almost zero, so we can deploy the automated redactor with confidence."
        )
    elif rec_pct >= 98:
        impact = (
            "We’re catching nearly everything that needs redaction—compliance risk is very low. "
            "A small fraction of over-masking remains and could be reviewed on demand."
        )
    elif prec_pct >= 95:
        impact = (
            "False alarms are rare, preserving readability. "
            "We miss a few items; we will consider refining patterns to raise catch rates further."
        )
    else:
        impact = (
            "Automated redaction results varied on this run. "
            "We recommend a manual review of the output to ensure all sensitive data is correctly masked "
            "and no non-sensitive content has been over-masked."
        )

    lines.append(impact)
    return "\n\n".join(lines)
