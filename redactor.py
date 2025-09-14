#AWS not required
import os
import json
import io
import csv
import re
import boto3
from datetime import datetime
from presidio_analyzer import AnalyzerEngine, RecognizerResult

# -------------------------------------------------------------------
# 1. AWS Comprehend client (credentials via env vars or IAM role)
# -------------------------------------------------------------------
comprehend = boto3.client(
    "comprehend",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
)

# -------------------------------------------------------------------
# 2. Presidio Analyzer for fallback on NER (especially NAME & ADDRESS)
# -------------------------------------------------------------------
analyzer = AnalyzerEngine()

# -------------------------------------------------------------------
# 3. PII Configuration
# -------------------------------------------------------------------
TARGET_PII_TYPES = {"NAME", "ADDRESS", "PHONE", "EMAIL", "DATE_OF_BIRTH", "SSN"}
TYPE_MAP = {"EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE"}
MASK_CHAR = "*"

# -------------------------------------------------------------------
# 4. Regex Patterns
# -------------------------------------------------------------------
FILLER_PATTERN = re.compile(r"\b(?:um+|hmm+|uh+|ah+|erm+)\b", re.IGNORECASE)

# Date‐of‐birth patterns (reuse existing)
PII_PATTERNS = {
    "DATE_OF_BIRTH": [
        re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b"),
        re.compile(r"\b\d{2}/\d{2}/(19|20)\d{2}\b"),
        re.compile(r"\b\d{2}-\d{2}-(19|20)\d{2}\b"),
        re.compile(
            r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
            r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)|"
            r"Dec(?:ember)?)\s\d{1,2},\s(19|20)\d{2}\b"
        ),
    ]
}

# Regex for EMAIL, PHONE, SSN
EMAIL_PATTERN = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b")
PHONE_PATTERN = re.compile(
    r"""\b
       (?:\+1[-.\s]?|1[-.\s]?)?          # optional country code
       (?:\(\d{3}\)|\d{3})              # area‐code with or w/o parens
       [-.\s]?                          # separator
       \d{3}                            # prefix
       [-.\s]?                          # separator
       \d{4}                            # line number
       (?:\s*(?:x|ext\.?)\s*\d{1,5})?   # optional extension
       \b
    """, re.VERBOSE)

SSN_PATTERN   = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

DOB_ANCHORS = [r"\bDOB\b", r"\bDate of birth\b", r"\bborn on\b"]

# -------------------------------------------------------------------
# 5. Helper Functions
# -------------------------------------------------------------------
def normalize_type(ent_type: str) -> str:
    return TYPE_MAP.get(ent_type, ent_type)

def remove_fillers(text: str) -> str:
    return FILLER_PATTERN.sub(lambda m: " " * len(m.group()), text)

def format_preserving_mask(value: str) -> str:
    if len(value) <= 2:
        return MASK_CHAR * len(value)
    return value[0] + MASK_CHAR * (len(value) - 2) + value[-1]

def accept_entity(ent: dict) -> bool:
    t, text = ent["Type"], ent["Text"]
    if t == "SSN":
        return bool(SSN_PATTERN.fullmatch(text))
    if t == "PHONE":
        return bool(PHONE_PATTERN.search(text))
    if t == "DATE_OF_BIRTH":
        return bool(re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", text))
    return True

def detect_dob_entities(sentence: str, confidence: float) -> list:
    patterns = PII_PATTERNS["DATE_OF_BIRTH"]
    anchors = any(re.search(a, sentence, re.IGNORECASE) for a in DOB_ANCHORS)
    results = []
    for pat in patterns:
        for m in pat.finditer(sentence):
            results.append({
                "Type":        "DATE_OF_BIRTH",
                "Text":        sentence[m.start():m.end()],
                "Confidence":  confidence,
                "BeginOffset": m.start(),
                "EndOffset":   m.end(),
                "Source":      "regex_fallback",
                "Anchored":    anchors,
            })
    return results

def extract_regex_entities(text: str) -> list:
    ents = []
    for pattern, ptype in [
        (EMAIL_PATTERN, "EMAIL"),
        (PHONE_PATTERN, "PHONE"),
        (SSN_PATTERN,   "SSN"),
    ]:
        for m in pattern.finditer(text):
            ents.append({
                "Type":         ptype,
                "Text":         text[m.start():m.end()],
                "Confidence":   0.5,
                "BeginOffset":  m.start(),
                "EndOffset":    m.end(),
                "Source":       "regex_fallback",
            })
    return ents

# -------------------------------------------------------------------
# 6. Core Masking Logic with Fallbacks
# -------------------------------------------------------------------
def mask_pii_with_comprehend(records: list, min_confidence: float = 0.6):
    audit_log = []
    for rec in records:
        sent = rec.get("sentence", "")
        vid  = rec.get("verbatim_id")
        if not sent or vid is None:
            continue

        clean_txt = remove_fillers(sent)

        # 6a. Try AWS Comprehend
        try:
            resp = comprehend.detect_pii_entities(
                Text=clean_txt, LanguageCode="en"
            )
            aws_entities = resp.get("Entities", [])
        except Exception:
            aws_entities = []

        entities = []
        # Collect high‐confidence AWS spans
        for e in aws_entities:
            ent_type = normalize_type(e["Type"])
            score    = round(e.get("Score", 0), 3)
            if ent_type in TARGET_PII_TYPES and score >= min_confidence:
                b, a = e["BeginOffset"], e["EndOffset"]
                raw = sent[b:a]
                entities.append({
                    "Type":         ent_type,
                    "Text":         raw,
                    "Confidence":   score,
                    "BeginOffset":  b,
                    "EndOffset":    a,
                    "Source":       "comprehend"
                })

        # 6b. Fallback Name & Address via Presidio (no confidence cutoff)
        pres_results = analyzer.analyze(
            text=clean_txt,
            entities=["PERSON","GPE","LOC","ORG"],
            language="en"
        )
        for r in pres_results:
            ptype = r.entity_type
            # Map PRESIDIO labels to our PII types
            if ptype in ("PERSON",):
                t = "NAME"
            elif ptype in ("GPE","LOC","ORG"):
                t = "ADDRESS"
            else:
                continue
            raw = sent[r.start : r.end]
            entities.append({
                "Type":         t,
                "Text":         raw,
                "Confidence":   round(r.score, 3),
                "BeginOffset":  r.start,
                "EndOffset":    r.end,
                "Source":       "presidio"
            })

        # 6c. Fallback DOB if missing
        if not any(e["Type"] == "DATE_OF_BIRTH" for e in entities):
            entities.extend(detect_dob_entities(clean_txt, min_confidence))

        # 6d. Fallback email, phone, SSN
        entities.extend(extract_regex_entities(clean_txt))

        # 6e. Apply masks in reverse order
        for e in sorted(entities, key=lambda x: x["BeginOffset"], reverse=True):
            m = format_preserving_mask(e["Text"])
            sent = sent[: e["BeginOffset"]] + m + sent[e["EndOffset"] :]
            audit_log.append({
                "verbatim_id": vid,
                "pii_type":    e["Type"],
                "original":    e["Text"],
                "masked":      m,
                "confidence":  e["Confidence"],
                "source":      e["Source"],
                "timestamp":   datetime.utcnow().isoformat(),
            })

        rec["sentence"] = sent

    return records, audit_log

# -------------------------------------------------------------------
# 7. File‐based API
# -------------------------------------------------------------------
def process_file(file_obj, min_confidence: float = 0.6):
    text = file_obj.read().decode("utf-8")
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = [json.loads(l) for l in text.splitlines() if l.strip()]

    redacted, audit = mask_pii_with_comprehend(records, min_confidence)
    redacted_json = json.dumps(redacted, ensure_ascii=False, indent=2)

    buf = io.StringIO()
    if audit:
        w = csv.DictWriter(buf, fieldnames=audit[0].keys())
        w.writeheader()
        w.writerows(audit)
    return redacted_json, buf.getvalue()

# -------------------------------------------------------------------
# 8. Single‐sentence API
# -------------------------------------------------------------------
def process_text(text: str, min_confidence: float = 0.6):
    recs, audit = mask_pii_with_comprehend(
        [{"sentence": text, "verbatim_id": 0}],
        min_confidence
    )
    masked = recs[0]["sentence"] if recs else text

    buf = io.StringIO()
    if audit:
        w = csv.DictWriter(buf, fieldnames=audit[0].keys())
        w.writeheader()
        w.writerows(audit)
    return masked, buf.getvalue()

"""#clean before detecting, AWS required
import os
import json
import io
import csv
import re
import boto3
from datetime import datetime

# 1. AWS Comprehend client (credentials via env vars or IAM role)
comprehend = boto3.client(
    "comprehend",
    region_name=os.getenv("AWS_REGION", "us-east-1")
)

# 2. PII configuration
TARGET_PII_TYPES = {"NAME", "ADDRESS", "PHONE", "EMAIL", "DATE_OF_BIRTH", "SSN"}
TYPE_MAP = {"EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE"}
MASK_CHAR = "*"

# 3. Regex patterns for PII detection & filler removal
FILLER_PATTERN = re.compile(r"\b(?:um+|hmm+|uh+|ah+|erm+)\b", re.IGNORECASE)

PII_PATTERNS = {
    "DATE_OF_BIRTH": [
        re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b"),
        re.compile(r"\b\d{2}/\d{2}/(19|20)\d{2}\b"),
        re.compile(r"\b\d{2}-\d{2}-(19|20)\d{2}\b"),
        re.compile(
            r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
            r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)|"
            r"Dec(?:ember)?)\s\d{1,2},\s(19|20)\d{2}\b"
        ),
    ]
}
DOB_ANCHORS = [r"\bDOB\b", r"\bDate of birth\b", r"\bborn on\b"]

# 4. Helper functions
def normalize_type(ent_type):
    return TYPE_MAP.get(ent_type, ent_type)

def clean_address(addr):
    return re.sub(r"\s+", " ", addr.strip(",. "))

def accept_entity(ent):
    t, text = ent["Type"], ent["Text"]
    if t == "SSN":
        return bool(re.fullmatch(r"\d{3}-\d{2}-\d{4}", text))
    if t == "PHONE":
        return bool(re.search(r"\d{3}.*\d{3}.*\d{4}", text))
    if t == "DATE_OF_BIRTH":
        return bool(re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", text))
    return True

def detect_dob_entities(sentence, confidence=0.6):
    patterns = PII_PATTERNS["DATE_OF_BIRTH"]
    anchors = [a for a in DOB_ANCHORS if re.search(a, sentence, re.IGNORECASE)]
    dob_entities = []
    for pattern in patterns:
        for match in re.finditer(pattern, sentence):
            dob_entities.append({
                "Type": "DATE_OF_BIRTH",
                "Text": match.group(),
                "Confidence": confidence,
                "BeginOffset": match.start(),
                "EndOffset": match.end(),
                "Source": "regex_fallback",
                "Anchored": bool(anchors)
            })
    return dob_entities

def remove_fillers(text):
    # Replace filler words with same-length spaces so offsets align
    return FILLER_PATTERN.sub(lambda m: " " * len(m.group()), text)

def format_preserving_mask(value: str) -> str:
    if len(value) <= 2:
        return MASK_CHAR * len(value)
    return value[0] + (MASK_CHAR * (len(value) - 2)) + value[-1]

# 5. Core masking logic with confidence threshold
def mask_pii_with_comprehend(records, min_confidence=0.6):
    audit_log = []

    for rec in records:
        sentence = rec.get("sentence", "")
        vid = rec.get("verbatim_id")
        if not sentence or vid is None:
            continue

        # a) Preprocess for detection
        detection_text = remove_fillers(sentence)

        # b) Call Comprehend
        resp = comprehend.detect_pii_entities(
            Text=detection_text, LanguageCode="en"
        )
        entities = []

        for e in resp.get("Entities", []):
            ent_type = normalize_type(e["Type"])
            score = round(e["Score"], 3)
            if ent_type not in TARGET_PII_TYPES or score < min_confidence:
                continue

            begin, end = e["BeginOffset"], e["EndOffset"]
            raw = sentence[begin:end]
            if ent_type == "ADDRESS":
                raw = clean_address(raw)

            ent = {
                "Type": ent_type,
                "Text": raw,
                "Confidence": score,
                "BeginOffset": begin,
                "EndOffset": end,
                "Source": "comprehend"
            }

            if accept_entity(ent):
                entities.append(ent)

        # c) Regex fallback for DOB if none found
        if not any(e["Type"] == "DATE_OF_BIRTH" for e in entities):
            for dob in detect_dob_entities(detection_text, min_confidence):
                begin, end = dob["BeginOffset"], dob["EndOffset"]
                raw = sentence[begin:end]
                dob.update({"Text": raw, "BeginOffset": begin, "EndOffset": end})
                if accept_entity(dob):
                    entities.append(dob)

        # d) Apply masks in reverse-offset order
        for e in sorted(entities, key=lambda x: x["BeginOffset"], reverse=True):
            masked = format_preserving_mask(e["Text"])
            sentence = (
                sentence[: e["BeginOffset"]]
                + masked
                + sentence[e["EndOffset"] :]
            )
            audit_log.append({
                "verbatim_id": vid,
                "pii_type": e["Type"],
                "original": e["Text"],
                "masked": masked,
                "confidence": e["Confidence"],
                "source": e["Source"],
                "timestamp": datetime.utcnow().isoformat()
            })

        rec["sentence"] = sentence

    return records, audit_log

# 6. File-based API
def process_file(file_obj, min_confidence=0.6):
    text = file_obj.read().decode("utf-8")
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = [
            json.loads(line)
            for line in text.splitlines()
            if line.strip()
        ]

    redacted, audit = mask_pii_with_comprehend(records, min_confidence)

    redacted_json = json.dumps(redacted, ensure_ascii=False, indent=2)

    buf = io.StringIO()
    if audit:
        writer = csv.DictWriter(buf, fieldnames=audit[0].keys())
        writer.writeheader()
        writer.writerows(audit)
    audit_csv = buf.getvalue()

    return redacted_json, audit_csv

# 7. Single-sentence API
def process_text(text, min_confidence=0.6):
    recs, audit = mask_pii_with_comprehend(
        [{"sentence": text, "verbatim_id": 0}], min_confidence
    )
    masked = recs[0]["sentence"] if recs else text

    buf = io.StringIO()
    if audit:
        writer = csv.DictWriter(buf, fieldnames=audit[0].keys())
        writer.writeheader()
        writer.writerows(audit)
    audit_csv = buf.getvalue()

    return masked, audit_csv
"""
''' #only file upload
import os
import json
import io
import csv
import re
import boto3
from datetime import datetime

# 1. Initialize AWS Comprehend client (credentials via env vars or IAM role)
comprehend = boto3.client(
    "comprehend",
    region_name=os.getenv("AWS_REGION", "us-east-1")
)

# 2. PII configuration
TARGET_PII_TYPES = {"NAME", "ADDRESS", "PHONE", "EMAIL", "DATE_OF_BIRTH", "SSN"}
TYPE_MAP = {"EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE"}
MASK_CHAR = "*"

# Regex patterns for fallback PII detection
PII_PATTERNS = {
    "DATE_OF_BIRTH": [
        re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b"),
        re.compile(r"\b\d{2}/\d{2}/(19|20)\d{2}\b"),
        re.compile(r"\b\d{2}-\d{2}-(19|20)\d{2}\b"),
        re.compile(r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
                   r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)|"
                   r"Dec(?:ember)?)\s\d{1,2},\s(19|20)\d{2}\b"),
    ]
}
DOB_ANCHORS = [
    r"\bDOB\b", r"\bDate of birth\b", r"\bborn on\b"
]

# 3. Helper functions
def normalize_type(t):
    return TYPE_MAP.get(t, t)

def clean_address(addr):
    return re.sub(r"\s+", " ", addr.strip(",. "))

def accept_entity(ent):
    t, text = ent["Type"], ent["Text"]
    if t == "SSN":
        return bool(re.fullmatch(r"\d{3}-\d{2}-\d{4}", text))
    if t == "PHONE":
        return bool(re.search(r"\d{3}.*\d{3}.*\d{4}", text))
    if t == "DATE_OF_BIRTH":
        return bool(re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", text))
    return True

def detect_dob_entities(sentence, confidence=0.6):
    patterns = PII_PATTERNS.get("DATE_OF_BIRTH", [])
    anchors = [a for a in DOB_ANCHORS if re.search(a, sentence, re.IGNORECASE)]
    dob_entities = []
    for pattern in patterns:
        for match in re.finditer(pattern, sentence):
            dob_entities.append({
                "Type": "DATE_OF_BIRTH",
                "Text": match.group(),
                "Confidence": confidence,
                "BeginOffset": match.start(),
                "EndOffset": match.end(),
                "Source": "regex_fallback",
                "Anchored": bool(anchors)
            })
    return dob_entities

def format_preserving_mask(value: str) -> str:
    if len(value) <= 2:
        return MASK_CHAR * len(value)
    return value[0] + (MASK_CHAR * (len(value) - 2)) + value[-1]

# 4. Core masking logic
def mask_pii_with_comprehend(records):
    audit_log = []
    for rec in records:
        sentence = rec.get("sentence", "")
        vid = rec.get("verbatim_id")
        if not sentence or vid is None:
            continue

        # a) Detect via Comprehend
        resp = comprehend.detect_pii_entities(Text=sentence, LanguageCode="en")
        entities = []
        for e in resp.get("Entities", []):
            t = normalize_type(e["Type"])
            if t not in TARGET_PII_TYPES:
                continue
            raw = sentence[e["BeginOffset"]:e["EndOffset"]]
            if t == "ADDRESS":
                raw = clean_address(raw)
            ent = {
                "Type": t,
                "Text": raw,
                "Confidence": round(e["Score"], 3),
                "BeginOffset": e["BeginOffset"],
                "EndOffset": e["EndOffset"],
                "Source": "comprehend"
            }
            if accept_entity(ent):
                entities.append(ent)

        # b) Fallback for DOB if missing
        if not any(e["Type"] == "DATE_OF_BIRTH" for e in entities):
            entities.extend(detect_dob_entities(sentence))

        # c) Apply masking in reverse order to preserve offsets
        for e in sorted(entities, key=lambda x: x["BeginOffset"], reverse=True):
            masked = format_preserving_mask(e["Text"])
            sentence = sentence[:e["BeginOffset"]] + masked + sentence[e["EndOffset"]:]
            audit_log.append({
                "verbatim_id": vid,
                "pii_type": e["Type"],
                "original": e["Text"],
                "masked": masked,
                "confidence": e.get("Confidence"),
                "source": e["Source"],
                "timestamp": datetime.utcnow().isoformat()
            })

        rec["sentence"] = sentence

    return records, audit_log

# 5. File-processing API
def process_file(file_obj):
    """
    Reads an uploaded JSON or JSONL file-like object,
    runs PII masking, and returns (redacted_json_str, audit_csv_str).
    """
    text = file_obj.read().decode("utf-8")
    # Attempt full JSON parse, otherwise JSONL
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    redacted, audit = mask_pii_with_comprehend(records)

    # Serialize JSON
    redacted_json = json.dumps(redacted, ensure_ascii=False, indent=2)

    # Serialize CSV
    buf = io.StringIO()
    if audit:
        writer = csv.DictWriter(buf, fieldnames=audit[0].keys())
        writer.writeheader()
        writer.writerows(audit)
    audit_csv = buf.getvalue()

    return redacted_json, audit_csv
'''
