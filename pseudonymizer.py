"""PII pseudonymization for content sent to the external LLM.

Single source of truth for masking PII before it leaves the server and
restoring it afterwards. Entities are replaced with numbered tags
([PERSON1], [EMAIL1], ...) via a Presidio custom operator. One shared
state dict per draft keeps the same real value mapped to the same tag
across the input email and every tool result in that draft.

The mapping is the sensitive artifact: it lives in memory for the
duration of a single draft() call and is discarded after restore. It is
never persisted and never sent to the model.

Flip PSEUDONYMIZE_ENABLED to turn the whole layer on. When off, every
function here is a passthrough and Presidio is never imported.
"""

import re
import sys
from collections import defaultdict

PSEUDONYMIZE_ENABLED = True

SPACY_MODEL = "en_core_web_lg"

USER_FIRST = "Morgan"
USER_LAST = "Rivers"
USER_FIRST_ALIASES = ["Daniel"]
USER_EMAILS = ["danielmorganrivers@gmail.com"]

USER_FIRST_TAG = "[USER_FIRST]"
USER_LAST_TAG = "[USER_LAST]"
USER_EMAIL_TAG = "[USER_EMAIL]"

STOPWORDS = frozenset({
    "will", "hope", "grace", "mark", "may", "june", "april", "august",
    "dawn", "rose", "art", "bill", "rich", "drew", "chase", "sky", "summer",
    "autumn", "brook", "reed", "victor", "joy", "faith", "crystal", "daisy",
    "ivy", "jean", "frank", "holly", "pearl", "ruby", "jade", "amber", "angel",
    "king", "prince", "major", "general", "miles", "wade", "penny", "sunny",
    "star", "cliff", "dale", "glen", "heath", "dean", "page", "sincerely",
    "regards", "best", "thanks", "dear", "hello", "cheers",
})


def _stop(token):
    return token.lower() in STOPWORDS


class UserIdentity:
    """Per-user masking identity: the account owner's own name/email, which
    are deterministically tagged before Presidio so the owner never varies by
    person-numbering. Compiled once per identity; passed into new_state so a
    shared process can hold one identity per user without global coupling."""

    def __init__(self, first, last, first_aliases=(), emails=()):
        assert first and last, "identity requires first and last name"
        self.first = first
        self.last = last
        self.first_aliases = list(first_aliases)
        self.emails = list(emails)
        self._rules = self._build_rules()

    def _build_rules(self):
        firsts = [self.first] + self.first_aliases
        rules = []
        for f in firsts:
            rules.append((
                re.compile(rf"\b{re.escape(f)}\s+{re.escape(self.last)}\b", re.IGNORECASE),
                f"{USER_FIRST_TAG} {USER_LAST_TAG}",
            ))
        for e in self.emails:
            rules.append((re.compile(re.escape(e), re.IGNORECASE), USER_EMAIL_TAG))
        rules.append((re.compile(rf"\b{re.escape(self.last)}\b"), USER_LAST_TAG))
        for f in firsts:
            rules.append((re.compile(rf"\b{re.escape(f)}\b"), USER_FIRST_TAG))
        return rules

    def mask_user(self, text):
        for rx, repl in self._rules:
            text = rx.sub(repl, text)
        return text

    def seed_mapping(self):
        mapping = {USER_FIRST_TAG: self.first, USER_LAST_TAG: self.last}
        if self.emails:
            mapping[USER_EMAIL_TAG] = self.emails[0]
        return mapping


DEFAULT_IDENTITY = UserIdentity(USER_FIRST, USER_LAST, USER_FIRST_ALIASES, USER_EMAILS)

# Presidio-detected PII (spaCy NER + built-in recognizers).
NER_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE"]

# Regex-detected secrets, added as custom PatternRecognizers so they share the
# same numbering, mapping, and span-conflict resolution as the NER entities.
# Each row: (entity_type, pattern_name, regex, score). Extend here to add more.
SECRET_PATTERNS = [
    ("API_KEY", "openai_deepseek_anthropic", r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b", 0.9),
    ("API_KEY", "aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", 0.9),
    ("API_KEY", "google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0.9),
    ("API_KEY", "slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", 0.9),
    ("API_KEY", "github_token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", 0.9),
    ("API_KEY", "langsmith_key", r"\blsv2_[a-z]{2}_[0-9a-f]{32}_[0-9a-f]{10}\b", 0.9),
    ("API_KEY", "bearer_token", r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}\b", 0.7),
    ("JWT", "jwt", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", 0.8),
    ("PRIVATE_KEY", "pem_block",
     r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
     0.99),
]

ENTITIES = NER_ENTITIES + sorted({row[0] for row in SECRET_PATTERNS})

_ANALYZER = None
_ANONYMIZER = None


def _build_engines():
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.operators import Operator, OperatorType

    class Pseudonymize(Operator):
        def operate(self, text, params):
            etype = params["entity_type"]
            if etype == "PERSON":
                return params["pindex"].get(text.lower().strip(), text)
            counters = params["counters"]
            seen = params["seen"]
            mapping = params["mapping"]
            key = (etype, text.lower().strip())
            if key not in seen:
                counters[etype] += 1
                tag = f"[{etype}{counters[etype]}]"
                seen[key] = tag
                mapping[tag] = text
            return seen[key]

        def validate(self, params):
            pass

        def operator_name(self):
            return "pseudonymize"

        def operator_type(self):
            return OperatorType.Anonymize

    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    grouped = defaultdict(list)
    for entity, name, regex, score in SECRET_PATTERNS:
        grouped[entity].append(Pattern(name=name, regex=regex, score=score))
    for entity, patterns in grouped.items():
        analyzer.registry.add_recognizer(
            PatternRecognizer(supported_entity=entity, patterns=patterns)
        )

    anonymizer = AnonymizerEngine()
    anonymizer.operators_factory.add_anonymize_operator(Pseudonymize)
    return analyzer, anonymizer


def _engines():
    global _ANALYZER, _ANONYMIZER
    if _ANALYZER is None:
        _ANALYZER, _ANONYMIZER = _build_engines()
    return _ANALYZER, _ANONYMIZER


def new_state(identity=None):
    """Fresh shared mapping for one draft, or None when disabled.

    identity is the account owner whose own name/email get fixed tags; defaults
    to DEFAULT_IDENTITY so single-tenant callers need pass nothing."""
    if not PSEUDONYMIZE_ENABLED:
        return None
    identity = identity or DEFAULT_IDENTITY
    return {
        "identity": identity,
        "counters": defaultdict(int),
        "seen": {},
        "mapping": identity.seed_mapping(),
        "names": {},
        "pindex": {},
        "persons": {},
        "token_index": {},
    }


def _person_tag(state, pid, surface, preferred_role):
    p = state["persons"][pid]
    key = surface.lower()
    if key in p["surftag"]:
        return p["surftag"][key]
    role = preferred_role
    if role in p["roles"]:
        n = 1
        while f"X{n}" in p["roles"]:
            n += 1
        role = f"X{n}"
    p["roles"][role] = surface
    tag = f"[PERSON{pid}_{role}]"
    p["surftag"][key] = tag
    state["mapping"].setdefault(tag, surface)
    state["names"].setdefault(surface, tag)
    state["pindex"].setdefault(key, tag)
    state["token_index"][key] = pid
    return tag


def _new_person(state):
    state["counters"]["PERSON"] += 1
    pid = state["counters"]["PERSON"]
    state["persons"][pid] = {"roles": {}, "surftag": {}}
    return pid


def _resolve_full(state, surface):
    tokens = [t for t in surface.split() if t]
    pid = None
    for t in tokens:
        pid = state["token_index"].get(t.lower())
        if pid:
            break
    if pid is None:
        pid = _new_person(state)
    n = len(tokens)
    parts = []
    for i, t in enumerate(tokens):
        if _stop(t):
            parts.append(t)
            continue
        role = "FIRST" if i == 0 else ("LAST" if i == n - 1 else f"MID{i}")
        parts.append(_person_tag(state, pid, t, role))
    comp = " ".join(parts)
    state["names"].setdefault(surface, comp)
    state["pindex"].setdefault(surface.lower(), comp)
    return comp


def _resolve_single(state, surface):
    if _stop(surface):
        return surface
    pid = state["token_index"].get(surface.lower())
    if pid is None:
        pid = _new_person(state)
    return _person_tag(state, pid, surface, "FIRST")


def _resolve_persons(state, results, text):
    surfaces = []
    for r in results:
        if r.entity_type == "PERSON":
            s = text[r.start:r.end].strip()
            if s:
                surfaces.append(s)
    surfaces.sort(key=lambda s: len(s.split()), reverse=True)
    for s in surfaces:
        if s.lower() in state["pindex"]:
            continue
        if len(s.split()) >= 2:
            _resolve_full(state, s)
        else:
            _resolve_single(state, s)


def _mask_names(text, state):
    names = state["names"]
    for surface in sorted(names, key=len, reverse=True):
        text = re.sub(rf"\b{re.escape(surface)}\b", names[surface], text)
    return text


def pseudonymize(text, state):
    """Replace PII in text with numbered tags, growing the shared state.

    Known names are masked deterministically before Presidio so a name seen
    earlier in the draft cannot be split or drift to a new tag. Presidio then
    detects any new PII; _resolve_persons groups co-referent name fragments
    under one person id and decomposes each into first/last role tags, so the
    model sees [PERSON1_FIRST] / [PERSON1_LAST] as the same identity.

    Passthrough when disabled or when text is empty.
    """
    if state is None or not text:
        return text
    from presidio_anonymizer.entities import OperatorConfig

    text = state["identity"].mask_user(text)
    text = _mask_names(text, state)
    analyzer, anonymizer = _engines()
    results = analyzer.analyze(text=text, language="en", entities=ENTITIES)
    if results:
        _resolve_persons(state, results, text)
        text = anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={"DEFAULT": OperatorConfig("pseudonymize", state)},
        ).text
    return text


def restore(text, state):
    """Replace tags with their original values, longest-tag-first.

    Longest-first prevents [PERSON1] from clobbering [PERSON11].
    Passthrough when disabled or when text is empty.
    """
    if state is None or not text:
        return text
    mapping = state["mapping"]
    for tag in sorted(mapping, key=len, reverse=True):
        text = text.replace(tag, mapping[tag])
    return text
