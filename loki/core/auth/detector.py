"""
Field type classifier.
Supports Dutch (NL) and English (EN) field labels, placeholders, and names.
"""
from __future__ import annotations
from loki.models.schema import FormField, FieldType, DetectedForm


# Dutch + English patterns per field type
_PATTERNS: dict[FieldType, list[str]] = {
    FieldType.EMAIL: [
        "email", "e-mail", "e-mailadres", "emailadres", "mail"
    ],
    FieldType.PASSWORD: [
        "wachtwoord", "password", "passwd", "paswoord", "ww", "nieuw wachtwoord", "new password"
    ],
    FieldType.PASSWORD_CONFIRM: [
        "herhaal wachtwoord", "bevestig wachtwoord", "confirm password", "retype",
        "repeat password", "wachtwoord herhalen", "wachtwoord bevestigen",
        "herhaal", "bevestig", "confirm", "verify"
    ],
    FieldType.LAST_NAME: [
        "achternaam", "last name", "lastname", "family name", "surname", "tussenvoegsel"
    ],
    FieldType.FIRST_NAME: [
        "voornaam", "first name", "firstname", "given name", "naam", "first", "naam"
    ],
    FieldType.USERNAME: [
        "gebruikersnaam", "username", "user name", "gebruiker", "login name"
    ],
    FieldType.PHONE: [
        "telefoon", "telefoonnummer", "phone", "mobile", "mobiel", "tel", "gsm"
    ],
    FieldType.DATE_OF_BIRTH: [
        "geboortedatum", "date of birth", "birthday", "dob", "geboorte"
    ],
}

_TYPE_MAP: dict[str, FieldType] = {
    "email": FieldType.EMAIL,
    "password": FieldType.PASSWORD,
    "tel": FieldType.PHONE,
}


def _normalize(text: str) -> str:
    return text.lower().strip()


def _match_field_type(
    label: str,
    placeholder: str,
    name_attr: str,
    input_type: str,
    autocomplete: str,
    already_has_password: bool = False,
) -> FieldType:
    """
    Classify a form field into a FieldType.
    Priority: autocomplete > input_type > pattern matching in label/placeholder/name.
    """
    # Priority 1: HTML autocomplete attribute
    ac = _normalize(autocomplete)
    ac_map = {
        "email": FieldType.EMAIL,
        "new-password": FieldType.PASSWORD,
        "current-password": FieldType.PASSWORD,
        "given-name": FieldType.FIRST_NAME,
        "family-name": FieldType.LAST_NAME,
        "username": FieldType.USERNAME,
        "tel": FieldType.PHONE,
        "bday": FieldType.DATE_OF_BIRTH,
    }
    if ac in ac_map:
        mm = ac_map[ac]
        if mm == FieldType.PASSWORD and already_has_password:
            return FieldType.PASSWORD_CONFIRM
        return mm

    # Priority 2: input type attribute
    if input_type in _TYPE_MAP:
        ft = _TYPE_MAP[input_type]
        # If we already have a password, this second one is confirm
        if ft == FieldType.PASSWORD and already_has_password:
            return FieldType.PASSWORD_CONFIRM
        return ft

    # Priority 3: pattern matching (Dutch + English)
    texts = [_normalize(t) for t in [label, placeholder, name_attr]]

    # Check confirm patterns first (must come before password patterns)
    for pattern in _PATTERNS[FieldType.PASSWORD_CONFIRM]:
        if any(pattern in t for t in texts):
            return FieldType.PASSWORD_CONFIRM

    for field_type, patterns in _PATTERNS.items():
        if field_type == FieldType.PASSWORD_CONFIRM:
            continue
        for pattern in patterns:
            if any(pattern in t for t in texts):
                if field_type == FieldType.PASSWORD and already_has_password:
                    return FieldType.PASSWORD_CONFIRM
                return field_type

    return FieldType.UNKNOWN


def classify_fields(form: dict) -> list[FormField]:
    """
    Given a raw form dict from detect_forms(), return classified FormField objects.
    Handles positional fallback for unclassified text inputs.
    """
    fields: list[FormField] = []
    has_password = False
    unknown_text_fields: list[int] = []  # indices in fields list

    for raw in form.get("fields", []):
        ft = _match_field_type(
            label=raw.get("label", ""),
            placeholder=raw.get("placeholder", ""),
            name_attr=raw.get("name_attr", ""),
            input_type=raw.get("input_type", "text"),
            autocomplete=raw.get("autocomplete", ""),
            already_has_password=has_password,
        )
        if ft == FieldType.PASSWORD:
            has_password = True

        field = FormField(
            selector=raw["selector"],
            field_type=ft,
            label=raw.get("label", ""),
            placeholder=raw.get("placeholder", ""),
            input_type=raw.get("input_type", "text"),
            autocomplete=raw.get("autocomplete", ""),
            name_attr=raw.get("name_attr", ""),
            required=raw.get("required", False),
        )
        if ft == FieldType.UNKNOWN and raw.get("input_type", "text") == "text":
            unknown_text_fields.append(len(fields))
        fields.append(field)

    # Positional fallback for unknown text fields
    name_types = [FieldType.FIRST_NAME, FieldType.LAST_NAME, FieldType.USERNAME]
    for i, field_idx in enumerate(unknown_text_fields):
        if i < len(name_types):
            fields[field_idx].field_type = name_types[i]

    return fields