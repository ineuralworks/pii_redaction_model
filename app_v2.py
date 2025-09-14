import os
import json
import time
import base64
import threading
from datetime import datetime
from io import StringIO

import requests
import pandas as pd
import streamlit as st

from redactor import process_file, process_text

# Import metrics functions
from metrics import (
    record_file_metrics,
    record_text_metrics,
    get_file_metrics_df,
    get_text_metrics_df,
    summarize_file_metrics,
    summarize_text_metrics,
    get_accuracy_df,
    summarize_accuracy,
    get_ground_truth_report,
)

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
st.set_page_config(page_title="📁 PII Redaction By Sam Okoye", layout="wide")
MIN_CONFIDENCE = 0.6
MAX_FILE_MB = 5

GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
REPO_OWNER   = "samokoye"
REPO_NAME    = "streamlit_app"
BRANCH        = "main"
LOG_FILE      = "error_logs.logs"

# -------------------------------------------------------------------
# Helpers: GitHub commits & error logging
# -------------------------------------------------------------------
def log_error_to_file(error_msg: str):
    """Append an error message with timestamp to LOG_FILE."""
    try:
        with open(LOG_FILE, "a") as f:
            ts = datetime.utcnow().isoformat()
            f.write(f"{ts} - {error_msg}\n")
    except Exception:
        print(f"Failed to write to {LOG_FILE}")

def commit_to_github(path: str, content: bytes, message: str):
    """Create a file in GitHub at `path` with `content`. Raises on HTTP errors."""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}"
    b64 = base64.b64encode(content).decode("utf-8")
    payload = {"message": message, "content": b64, "branch": BRANCH}
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    resp = requests.put(url, json=payload, headers=headers)
    resp.raise_for_status()

def commit_async(path: str, content: bytes, message: str):
    """Fire-and-forget commit to GitHub, logs failures."""
    def _worker():
        try:
            commit_to_github(path, content, message)
        except Exception as e:
            log_error_to_file(f"Commit failed for {path}: {e}")
    threading.Thread(target=_worker, daemon=True).start()

# -------------------------------------------------------------------
# UI: Title & Mode selector
# -------------------------------------------------------------------
st.title("📞 PII Redaction")
st.markdown("Upload a JSON/TXT or enter a sentence, and see live PII redaction.")

mode = st.radio("Select Input Mode", ["Upload File", "Single Sentence"])

# -------------------------------------------------------------------
# Function to render audit DataFrame
# -------------------------------------------------------------------
def render_audit(audit_csv: str, show_preview: bool):
    df = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()
    if df.empty:
        st.warning("No PII detected; audit log is empty.")
        return

    with st.expander("📊 PII Summary", expanded=True):
        st.bar_chart(df["pii_type"].value_counts())
        top5 = (
            df["verbatim_id"]
              .value_counts()
              .head(5)
              .rename_axis("verbatim_id")
              .reset_index(name="count")
        )
        st.table(top5)

    if show_preview:
        with st.expander("📋 Audit Log Preview", expanded=False):
            st.dataframe(df.head(10))

    st.subheader("📄 Download Audit CSV")
    st.download_button(
        label="Download CSV",
        data=audit_csv,
        file_name="audit.csv",
        mime="text/csv",
    )

# -------------------------------------------------------------------
# Mode: Upload File
# -------------------------------------------------------------------
if mode == "Upload File":
    show_preview = st.checkbox("Show audit log preview", value=False)
    uploaded_file = st.file_uploader(
        "Upload a .json or .txt file", type=["json", "txt"]
    )

    if uploaded_file:
        size_mb = uploaded_file.size / (1024 * 1024)
        if size_mb > MAX_FILE_MB:
            st.error(f"File size {size_mb:.2f} MB exceeds {MAX_FILE_MB} MB limit.")
        else:
            # Read raw bytes and commit input
            raw_bytes = uploaded_file.read()
            ts        = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            date      = datetime.utcnow().strftime("%m%d%Y")
            input_path = f"inputs/{date}/{ts}_{uploaded_file.name}"
            commit_async(input_path, raw_bytes, f"Input upload @ {ts}")

            # Reset and run redaction with timing
            uploaded_file.seek(0)
            start_ts = time.time()
            with st.spinner("Redacting PII..."):
                redacted_json, audit_csv = process_file(
                    uploaded_file, MIN_CONFIDENCE
                )
            end_ts = time.time()

            # Commit redacted output asynchronously
            base, ext   = os.path.splitext(uploaded_file.name)
            out_name    = f"{base}_redacted{ext}"
            output_path = f"outputs/{date}/{ts}_{out_name}"
            commit_async(
                output_path,
                redacted_json.encode("utf-8"),
                f"Redacted output @ {ts}",
            )

            # Parse audit and record metrics (incl. accuracy if ground_truth)
            df_audit    = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()
            record_count = len(json.loads(redacted_json))
            record_file_metrics(
                file_name       = uploaded_file.name,
                start_ts        = start_ts,
                end_ts          = end_ts,
                pii_count       = len(df_audit),
                record_count    = record_count,
                audit_gen_ts    = end_ts,
                raw_file_bytes  = raw_bytes,
                audit_csv       = audit_csv,
            )

            # Render results
            st.subheader("🔒 Redacted JSON Output")
            st.code(redacted_json, language="json")
            render_audit(audit_csv, show_preview)
            # -------------------------------------------------------------------
            # Download Ground-Truth Report (if this was a ground_truth file)
            # -------------------------------------------------------------------
            gt_csv = get_ground_truth_report(uploaded_file.name)
            if gt_csv:
                st.subheader("📥 Ground-Truth Report")
                st.download_button(
                    label="Download Ground-Truth CSV",
                    data=gt_csv,
                    file_name=f"ground_truth_report_{uploaded_file.name}.csv",
                    mime="text/csv",
                )

# -------------------------------------------------------------------
# Mode: Single Sentence
# -------------------------------------------------------------------
else:
    show_preview_txt = st.checkbox("Show audit log preview", value=False)
    text_input       = st.text_area("Enter a sentence to mask")

    if st.button("Mask Sentence"):
        sentence = text_input.strip()
        if not sentence:
            st.error("Please enter a sentence to process.")
        else:
            ts      = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            date    = datetime.utcnow().strftime("%m%d%Y")
            in_path = f"inputs/{date}/{ts}_sentence.txt"
            commit_async(
                in_path,
                sentence.encode("utf-8"),
                f"Sentence input @ {ts}"
            )

            start_ts = time.time()
            with st.spinner("Detecting & masking PII..."):
                masked_sentence, audit_csv = process_text(
                    sentence, MIN_CONFIDENCE
                )
            end_ts = time.time()

            # Commit masked sentence
            out_path = f"outputs/{date}/{ts}_sentence_redacted.txt"
            commit_async(
                out_path,
                masked_sentence.encode("utf-8"),
                f"Sentence redacted @ {ts}"
            )

            # Record text metrics
            df_audit = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()
            record_text_metrics(
                start_ts     = start_ts,
                end_ts       = end_ts,
                pii_count    = len(df_audit),
                audit_gen_ts = end_ts
            )

            # Render results
            st.subheader("🔒 Masked Sentence")
            st.write(masked_sentence)
            render_audit(audit_csv, show_preview_txt)

# -------------------------------------------------------------------
# Metrics Dashboard
# -------------------------------------------------------------------
st.markdown("---")
st.subheader("📊 Metrics Dashboard")

# File‐level summary
file_summary = summarize_file_metrics()
if file_summary:
    st.markdown("**File Processing Summary**")
    st.json(file_summary)
    st.markdown("Detailed File Metrics:")
    st.dataframe(get_file_metrics_df())

# Text‐level summary
text_summary = summarize_text_metrics()
if text_summary:
    st.markdown("**Single‐Sentence Summary**")
    st.json(text_summary)
    st.markdown("Detailed Text Metrics:")
    st.dataframe(get_text_metrics_df())

# Accuracy summary for any ground_truth uploads
accuracy_summary = summarize_accuracy()
if accuracy_summary:
    st.markdown("**🧮 Accuracy on Synthetic Ground-Truth**")
    st.json(accuracy_summary)
    st.markdown("Detailed Accuracy Records:")
    st.dataframe(get_accuracy_df())

