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
from urllib.parse import quote

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
    generate_business_summary,
    _init_session_metrics,
)

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
st.set_page_config(page_title="📁 PII Redaction By Sam Okoye", layout="wide")
# -------------------------------------------------------------------
# Session metrics init & timeout
# -------------------------------------------------------------------
_init_session_metrics()
SESSION_TIMEOUT = 120  # seconds(2 mins max)

if "last_activity" not in st.session_state:
    st.session_state.last_activity = time.time()
else:
    if time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
        st.session_state.file_metrics.clear()
        st.session_state.text_metrics.clear()
        st.session_state.accuracy_results.clear()
        st.session_state.ground_truth_reports.clear()

st.session_state.last_activity = time.time()
#MIN_CONFIDENCE = 0.6
# -------------------------------------------------------------------
# Settings Sidebar: Confidence Threshold
# -------------------------------------------------------------------
st.sidebar.markdown("## ⚙️ Settings")
MIN_CONFIDENCE = st.sidebar.slider(
    "Set minimum confidence to redact PII. default is 0.5",
    min_value=0.0,
    max_value=1.0,
    value=0.5,
    step=0.01,
)
st.sidebar.write(f"Current confidence threshold: **{MIN_CONFIDENCE:.2f}**")

MAX_FILE_MB    = 5

GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
REPO_OWNER   = "ineuralworks"
REPO_NAME    = "pii_redaction_model"
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
    """
    Create or update a file in GitHub at `path` with `content`.
    If the file exists, fetch its `sha` and include it in the PUT payload.
    """
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    # First, see if the file already exists (to grab its sha)
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        existing_sha = resp.json().get("sha")
    except requests.exceptions.HTTPError as e:
        # 404 means file not found → this will create a new one
        existing_sha = None
    except Exception as e:
        log_error_to_file(f"Error checking existence of {path}: {e}")
        existing_sha = None

    # Build payload
    b64_content = base64.b64encode(content).decode("utf-8")
    payload = {
        "message": message,
        "content": b64_content,
        "branch": BRANCH,
    }
    if existing_sha:
        payload["sha"] = existing_sha

    # Create or update
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
st.title("📞 PII Redaction Model")
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
            # use st.table to avoid column overlap/jumble
            st.table(df.head(10))

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
            # 1) Read raw bytes and prepare timestamps
            raw_bytes = uploaded_file.read()
            ts        = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            date      = datetime.utcnow().strftime("%m%d%Y")

            # 2) Cache key per filename
            cache_key = f"cache_{uploaded_file.name}"
            if cache_key not in st.session_state:
                # a) Commit original input
                input_path = f"inputs/{date}/{ts}_{uploaded_file.name}"
                commit_async(input_path, raw_bytes, f"Input upload @ {ts}")

                # b) Run redaction once
                uploaded_file.seek(0)
                start_ts = time.time()
                with st.spinner(f"Redacting PII at {MIN_CONFIDENCE:.2f} confidence…"):
                    redacted_json, audit_csv = process_file(uploaded_file, MIN_CONFIDENCE)
                end_ts = time.time()

                # c) Commit redacted output
                base, ext   = os.path.splitext(uploaded_file.name)
                out_name    = f"{base}_redacted{ext}"
                output_path = f"outputs/{date}/{ts}_{out_name}"
                commit_async(output_path, redacted_json.encode("utf-8"), f"Redacted output @ {ts}")

                # d) Store in session_state
                st.session_state[cache_key] = {
                    "raw_bytes":     raw_bytes,
                    "start_ts":      start_ts,
                    "end_ts":        end_ts,
                    "redacted_json": redacted_json,
                    "audit_csv":     audit_csv,
                }

            # 3) Retrieve from cache
            cache         = st.session_state[cache_key]
            raw_bytes     = cache["raw_bytes"]
            start_ts      = cache["start_ts"]
            end_ts        = cache["end_ts"]
            redacted_json = cache["redacted_json"]
            audit_csv     = cache["audit_csv"]

            # 4) Record file metrics (runs every rerun, redaction is cached)
            df_audit     = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()
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

            # 5) Embed full JSON via iframe
            quoted   = quote(redacted_json)
            data_url = f"data:text/plain;charset=utf-8,{quoted}"
            st.markdown(
                f'''
                <iframe
                  src="{data_url}"
                  style="width:100%; height:600px; border:1px solid #ddd;"
                ></iframe>
                ''',
                unsafe_allow_html=True
            )

            # 6) Download full JSON
            out_name = f"{os.path.splitext(uploaded_file.name)[0]}_redacted{os.path.splitext(uploaded_file.name)[1]}"
            st.download_button(
                label="⬇️ Download Full JSON",
                data=redacted_json.encode("utf-8"),
                file_name=out_name,
                mime="application/json",
            )

            # 7) Render audit DataFrame (with optional preview)
            render_audit(audit_csv, show_preview)

            # 8) Ground-Truth report download (if present)
            gt_csv = get_ground_truth_report(uploaded_file.name)
            if gt_csv:
                st.subheader("📥 Ground-Truth Report")
                st.download_button(
                    label="Download Ground-Truth CSV",
                    data=gt_csv,
                    file_name=f"ground_truth_report_{uploaded_file.name}.csv",
                    mime="text/csv",
                )

            # 9) Business summary (safely returns None for non-GT files)
            summary = generate_business_summary(uploaded_file.name)
            if summary:
                st.markdown(summary)

# # -------------------------------------------------------------------
# # Mode: Upload File
# # -------------------------------------------------------------------
# if mode == "Upload File":
#     show_preview = st.checkbox("Show audit log preview", value=False)
#     uploaded_file = st.file_uploader(
#         "Upload a .json or .txt file", type=["json", "txt"]
#     )

#     if uploaded_file:
#         size_mb = uploaded_file.size / (1024 * 1024)
#         if size_mb > MAX_FILE_MB:
#             st.error(f"File size {size_mb:.2f} MB exceeds {MAX_FILE_MB} MB limit.")
#         else:
#             # Read raw bytes (for GitHub commit and metrics)
#             raw_bytes = uploaded_file.read()
#             ts        = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
#             date      = datetime.utcnow().strftime("%m%d%Y")
#             input_path = f"inputs/{date}/{ts}_{uploaded_file.name}"
#             commit_async(input_path, raw_bytes, f"Input upload @ {ts}")

#             # Rewind and run redaction
#             uploaded_file.seek(0)
#             start_ts = time.time()
#             with st.spinner(f"Redacting PII at {MIN_CONFIDENCE:.2f} confidence…"):
#                 redacted_json, audit_csv = process_file(
#                     uploaded_file, MIN_CONFIDENCE
#                 )
#             end_ts = time.time()

#             # Commit redacted output asynchronously
#             base, ext   = os.path.splitext(uploaded_file.name)
#             out_name    = f"{base}_redacted{ext}"
#             output_path = f"outputs/{date}/{ts}_{out_name}"
#             commit_async(
#                 output_path,
#                 redacted_json.encode("utf-8"),
#                 f"Redacted output @ {ts}",
#             )

#             # Parse audit and record metrics
#             df_audit     = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()
#             record_count = len(json.loads(redacted_json))
#             record_file_metrics(
#                 file_name       = uploaded_file.name,
#                 start_ts        = start_ts,
#                 end_ts          = end_ts,
#                 pii_count       = len(df_audit),
#                 record_count    = record_count,
#                 audit_gen_ts    = end_ts,
#                 raw_file_bytes  = raw_bytes,
#                 audit_csv       = audit_csv,
#             )

#             # Render redacted JSON
#             # st.subheader("🔒 Redacted JSON Output")
#             # st.code(redacted_json, language="json")
#             # ── Redacted JSON Preview & Full Output ──
#             # after your download button, build a text/plain data-URI
#             quoted = quote(redacted_json)
#             data_url = f"data:text/plain;charset=utf-8,{quoted}"
#             # 1) embed via iframe (in-page “new window”)
#             st.markdown(
#                 f'''
#                 <iframe
#                   src="{data_url}"
#                   style="width:100%; height:600px; border:1px solid #ddd;"
#                 ></iframe>
#                 ''',
#                 unsafe_allow_html=True
#             )
            
#             # 2) Download full JSON
#             out_name = f"{os.path.splitext(uploaded_file.name)[0]}_redacted{os.path.splitext(uploaded_file.name)[1]}"
#             st.download_button(
#                 label="⬇️ Download Full JSON",
#                 data=redacted_json.encode("utf-8"),
#                 file_name=out_name,
#                 mime="application/json",
#             )
            
            

#             # Render audit and download buttons
#             render_audit(audit_csv, show_preview)

#             # Download ground-truth report, if available
#             gt_csv = get_ground_truth_report(uploaded_file.name)
#             if gt_csv:
#                 st.subheader("📥 Ground-Truth Report")
#                 st.download_button(
#                     label="Download Ground-Truth CSV",
#                     data=gt_csv,
#                     file_name=f"ground_truth_report_{uploaded_file.name}.csv",
#                     mime="text/csv",
#                 )
#             # Only now do we generate the summary
#             summary = generate_business_summary(uploaded_file.name)
#             if summary:
#                 st.markdown(summary)


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
            with st.spinner(f"Redacting PII at {MIN_CONFIDENCE:.2f} confidence…"):
                masked_sentence, audit_csv = process_text(
                    sentence, MIN_CONFIDENCE
                )
            end_ts = time.time()

            out_path = f"outputs/{date}/{ts}_sentence_redacted.txt"
            commit_async(
                out_path,
                masked_sentence.encode("utf-8"),
                f"Sentence redacted @ {ts}"
            )

            df_audit = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()
            record_text_metrics(
                start_ts     = start_ts,
                end_ts       = end_ts,
                pii_count    = len(df_audit),
                audit_gen_ts = end_ts
            )

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
