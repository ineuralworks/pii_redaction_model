import streamlit as st
import pandas as pd
from io import StringIO
from redactor import process_file, process_text

# Config
st.set_page_config(page_title="PII Redaction By Sam Okoye", layout="wide")
MIN_CONFIDENCE = 0.6
MAX_FILE_MB = 5

# Title and description
st.title("📞PII Redaction By Sam Okoye")
st.markdown(
    "Choose an input mode, set an optional preview toggle, and see how PII is "
    "masked using Comprehend + regex fallback (confidence ≥ 0.6)."
)

# Mode selector
mode = st.radio("Select Input Mode", ["Upload File", "Single Sentence"])

if mode == "Upload File":
    show_preview = st.checkbox("Show audit log preview", value=False)
    uploaded_file = st.file_uploader("Upload a .json or .txt file", type=["json", "txt"])

    if uploaded_file:
        file_mb = uploaded_file.size / (1024 * 1024)
        if file_mb > MAX_FILE_MB:
            st.error(f"File size {file_mb:.2f} MB exceeds {MAX_FILE_MB} MB limit.")
        else:
            with st.spinner("Redacting PII..."):
                try:
                    redacted_json, audit_csv = process_file(uploaded_file, MIN_CONFIDENCE)
                except Exception as e:
                    st.error(f"Processing failed: {e}")
                    st.stop()

            st.subheader("🔒 Redacted JSON Output")
            st.code(redacted_json, language="json")

            df_audit = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()

            if not df_audit.empty:
                # PII Summary
                with st.expander("📊 PII Summary", expanded=True):
                    st.bar_chart(df_audit["pii_type"].value_counts())
                    st.write("Top records by redaction count:")
                    st.table(
                        df_audit["verbatim_id"]
                        .value_counts()
                        .head(5)
                        .rename_axis("verbatim_id")
                        .reset_index(name="count")
                    )

                # Optional Audit Preview
                if show_preview:
                    with st.expander("📋 Audit Log Preview"):
                        st.dataframe(df_audit.head(10))

                # Download CSV
                st.subheader("📄 Download Audit CSV")
                st.download_button(
                    label="Download CSV",
                    data=audit_csv,
                    file_name="audit.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No PII detected; audit log is empty.")

else:  # Single Sentence mode
    show_preview_txt = st.checkbox("Show audit log preview", value=False)
    text_input = st.text_area("Enter a sentence to mask")

    if st.button("Mask Sentence"):
        if not text_input.strip():
            st.error("Please enter a sentence to process.")
        else:
            with st.spinner("Detecting & masking PII..."):
                try:
                    masked_sentence, audit_csv = process_text(text_input, MIN_CONFIDENCE)
                except Exception as e:
                    st.error(f"Processing failed: {e}")
                    st.stop()

            st.subheader("🔒 Masked Sentence")
            st.write(masked_sentence)

            df_audit = pd.read_csv(StringIO(audit_csv)) if audit_csv.strip() else pd.DataFrame()

            if not df_audit.empty:
                with st.expander("📊 PII Summary", expanded=True):
                    st.bar_chart(df_audit["pii_type"].value_counts())

                if show_preview_txt:
                    with st.expander("📋 Audit Log Preview"):
                        st.dataframe(df_audit)
            else:
                st.warning("No PII detected in input sentence.")
if False:
    """
    #file upload only
import streamlit as st
import pandas as pd
from io import StringIO
from redactor import process_file

# Page config
st.set_page_config(
    page_title="PII Redaction Demo",
    layout="wide"
)

st.title("📞PII Redaction Demo")
st.markdown(
    "Upload a JSON/TXT file containing call transcripts and see live "
    "PII redaction powered by Amazon Comprehend + regex fallback."
)

# File uploader
uploaded_file = st.file_uploader(
    "Choose a .json or .txt file", type=["json", "txt"]
)

if uploaded_file:
    # 3. UX: enforce file-size limit
    max_mb = 5
    file_mb = uploaded_file.size / (1024 * 1024)
    if file_mb > max_mb:
        st.error(f"File size {file_mb:.2f} MB exceeds the {max_mb} MB limit.")
    else:
        # 2. UX: show spinner during redaction
        with st.spinner("Redacting PII..."):
            try:
                redacted_json, audit_csv = process_file(uploaded_file)
            except Exception as e:
                st.error(f"Processing failed: {e}")
                st.stop()

        # Display redacted JSON
        st.subheader("🔒 Redacted JSON Output")
        st.code(redacted_json, language="json")

        # Parse audit CSV into DataFrame
        if audit_csv.strip():
            df_audit = pd.read_csv(StringIO(audit_csv))

            # 1. PII Summary panel
            with st.expander("📊 PII Summary", expanded=True):
                with st.spinner("Summarizing PII counts..."):
                    type_counts = df_audit["pii_type"].value_counts()
                    vid_counts = df_audit["verbatim_id"].value_counts()

                    st.write("**Redactions by PII Type**")
                    st.bar_chart(type_counts)

                    st.write("**Top Records by Redaction Count**")
                    st.table(vid_counts.head(5).rename_axis("verbatim_id").reset_index(name="count"))

            # 2. Audit Log preview
            with st.expander("📋 Audit Log Preview", expanded=False):
                st.dataframe(df_audit.head(10))

            # Download button
            st.subheader("📄 Download Audit CSV")
            st.download_button(
                label="Download CSV",
                data=audit_csv,
                file_name="audit.csv",
                mime="text/csv"
            )
        else:
            st.warning("No PII detected; audit log is empty.")
"""
