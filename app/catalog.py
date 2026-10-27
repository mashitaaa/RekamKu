from __future__ import annotations

SPECIFIC = "specific"
GENERAL = "general"

CATEGORIES = {
    "identity": {
        "title": "Identity",
        "short": "Identity",
        "noun": "identity document",
        "hint": "Scans of your ID card (KTP) and BPJS or insurance card, needed when you register at a clinic or hospital.",
        "examples": ["KTP", "BPJS card", "Insurance card"],
        "exts": ["jpg", "jpeg", "png", "pdf"],
        "max_mb": 10,
        "data_type": "Scanned identity documents",
        "class": SPECIFIC,
        "basis": "KTP: name, NIK, address (Art. 4(3) a, f) and a face photo (potentially biometric, Art. 4(2) b; "
                 "RekamKu does not run face recognition). "
                 "The BPJS card reveals use of health services (Art. 4(2) a).",
        "placeholder": "e.g. KTP, valid for life",
    },
    "documents": {
        "title": "Medical documents",
        "short": "Documents",
        "noun": "medical document",
        "hint": "Lab results, discharge summaries, referral letters, or your blood pressure and sugar logs (PDF, Word, Excel).",
        "examples": ["Lab results", "Discharge summary", "BP & sugar log"],
        "exts": ["pdf", "docx", "xlsx", "doc", "xls"],
        "max_mb": 25,
        "data_type": "Office documents (PDF, DOCX, XLSX)",
        "class": SPECIFIC,
        "basis": "Health data and information (Art. 4(2) a): records relating to physical or mental health "
                 "and/or health services.",
        "placeholder": "e.g. RSUD lab, October 2026",
    },
    "videos": {
        "title": "Medical videos",
        "short": "Videos",
        "noun": "medical video",
        "hint": "Symptom recordings your doctor asked for (seizures, tremor, sleep apnoea), pregnancy ultrasound clips, "
                "or physiotherapy exercises recorded during a session.",
        "examples": ["Seizure recording", "Ultrasound clip", "Physio exercises"],
        "exts": ["mp4", "webm", "mov"],
        "max_mb": 200,
        "data_type": "Video",
        "class": SPECIFIC,
        "basis": "Records a health condition (Art. 4(2) a) and usually the patient's face "
                 "(potentially biometric, Art. 4(2) b).",
        "placeholder": "e.g. Night-time seizure, 2 minutes",
    },
}

MIME = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "doc": "application/msword", "xls": "application/vnd.ms-excel",
    "mp4": "video/mp4", "webm": "video/webm", "mov": "video/quicktime",
}
INLINE = {"jpg", "jpeg", "png", "mp4", "webm", "mov"}


def sniff(ext: str, head: bytes) -> bool:
    if ext in ("jpg", "jpeg"):
        return head[:3] == b"\xff\xd8\xff"
    if ext == "png":
        return head[:8] == b"\x89PNG\r\n\x1a\n"
    if ext == "pdf":
        return head[:5] == b"%PDF-"
    if ext in ("docx", "xlsx"):
        return head[:4] == b"PK\x03\x04"
    if ext in ("doc", "xls"):
        return head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    if ext in ("mp4", "mov"):
        return head[4:8] == b"ftyp" or head[4:8] in (b"moov", b"wide", b"mdat")
    if ext == "webm":
        return head[:4] == b"\x1a\x45\xdf\xa3"
    return False


PROFILE_FIELDS = [
    ("name", "Full name", "identity", GENERAL, "Art. 4(3) a", "As written on your KTP", "text"),
    ("nik", "NIK (national ID number)", "identity", GENERAL, "Art. 4(3) f; links to population records",
     "16 digits on your KTP", "nik"),
    ("birth_date", "Date of birth", "identity", GENERAL, "Art. 4(3) f", "", "date"),
    ("sex", "Sex", "identity", GENERAL, "Art. 4(3) b", "", "sex"),
    ("phone", "Phone number", "identity", GENERAL, "Art. 4(3) f", "e.g. 081234567890", "tel"),
    ("address", "Address", "identity", GENERAL, "Art. 4(3) f", "", "textarea"),
    ("bpjs", "BPJS Kesehatan number", "health", SPECIFIC, "Art. 4(2) a (health services)",
     "13 digits on your JKN card", "digits"),
    ("blood_type", "Blood type", "health", SPECIFIC, "Art. 4(2) a", "", "blood"),
    ("allergies", "Drug or food allergies", "health", SPECIFIC, "Art. 4(2) a", "e.g. amoxicillin, shrimp", "text"),
    ("conditions", "Conditions or diagnoses", "health", SPECIFIC, "Art. 4(2) a", "e.g. epilepsy, hypertension",
     "textarea"),
    ("medications", "Regular medication", "health", SPECIFIC, "Art. 4(2) a", "Drug and dose, one per line",
     "textarea"),
    ("emergency_name", "Emergency contact name", "emergency", GENERAL, "Third-party personal data (Art. 4(3))",
     "", "text"),
    ("emergency_phone", "Emergency contact phone", "emergency", GENERAL, "Third-party personal data (Art. 4(3))",
     "", "tel"),
]
PROFILE_GROUPS = [
    ("identity", "Identity", "Used to match you with documents from hospitals and clinics."),
    ("health", "Health", "The summary doctors usually ask for at the start of a consultation."),
    ("emergency", "Emergency contact", "The person to call if you cannot speak for yourself."),
]
BLOOD_TYPES = ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-", "Unknown"]
SEXES = ["", "Female", "Male"]

NOT_ENCRYPTED = [
    ("Random IDs (UUIDs) linking a file to its account", "Needed to find a user's rows. They are random, so they "
     "reveal nothing about the patient and cannot be guessed."),
    ("Username lookup index (HMAC-SHA256)", "Needed to find the account at sign-in, before any user key exists. "
     "It is a keyed hash: without the server secret it cannot be reversed or even tested against a guess."),
    ("Salts and scrypt parameters", "Must be read before the password can be checked. Like the salt of any "
     "password hash, they are not secret and reveal nothing."),
    ("Public half of the activity-log key (X25519)", "Lets the server record events such as a failed sign-in "
     "while the vault is locked. It is public by definition; only the owner's private key can read the log."),
    ("Size of each encrypted file on disk", "Inherent to storing a file. Padding every video to a fixed size "
     "would waste a lot of storage; the size alone does not reveal what the file contains."),
]
