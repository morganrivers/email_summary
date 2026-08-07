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

import importlib.util
import re
import sys
from collections import defaultdict

PSEUDONYMIZE_ENABLED = True

SPACY_MODEL = "en_core_web_lg"

USER_FIRST = "Morgan"
USER_LAST = "Rivers"
USER_FIRST_ALIASES = ["Daniel"]
USER_EMAILS = ["danielmorganrivers@gmail.com"]
# Placeholders the multi-tenant account store (B1) fills from the OAuth
# profile + address book. Empty in single-tenant so DEFAULT_IDENTITY is unchanged.
USER_PHONES = []
USER_CONTACTS = []

USER_FIRST_TAG = "[USER_FIRST]"
USER_LAST_TAG = "[USER_LAST]"
USER_EMAIL_TAG = "[USER_EMAIL]"
USER_PHONE_TAG = "[USER_PHONE]"

# A phone-like run: a digit, then 5+ of digit/space/()-.+, then a digit, not
# glued to word characters. Candidates are digit-normalized before comparison so
# spacing, dashes, dots, parens, and +country-code all match one configured number.
_PHONE_RUN = re.compile(r"(?<!\w)\+?\d[\d\s().\-]{5,}\d(?!\w)")
_MIN_PHONE_DIGITS = 7


def _digits(s):
    return re.sub(r"\D", "", s)

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

    def __init__(self, first, last, first_aliases=(), emails=(), phones=(), contacts=(), account_id="default",
                 analyzer=True):
        assert first and last, "identity requires first and last name"
        assert account_id, "identity requires an account_id"
        self.account_id = account_id
        self.analyzer = bool(analyzer)
        self.first = first
        self.last = last
        self.first_aliases = list(first_aliases)
        self.emails = list(emails)
        self.contacts = [" ".join(c.split()) for c in contacts if c.strip()]
        # Kept so an identity can be copied faithfully. Masking uses the digit
        # runs below; without the originals a copy silently loses every phone,
        # which is a masking gap rather than a cosmetic one.
        self.phones = list(phones)
        self._phone_digits = []
        for p in phones:
            d = _digits(p)
            assert len(d) >= _MIN_PHONE_DIGITS, f"phone {p!r} has too few digits to mask safely"
            self._phone_digits.append(d)
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
        return self._mask_phones(text)

    def _mask_phones(self, text):
        if not self._phone_digits:
            return text

        def repl(m):
            cand = _digits(m.group(0))
            if len(cand) < _MIN_PHONE_DIGITS:
                return m.group(0)
            for pd in self._phone_digits:
                if cand == pd or cand.endswith(pd) or pd.endswith(cand):
                    return USER_PHONE_TAG
            return m.group(0)

        return _PHONE_RUN.sub(repl, text)

    def seed_mapping(self):
        mapping = {USER_FIRST_TAG: self.first, USER_LAST_TAG: self.last}
        if self.emails:
            mapping[USER_EMAIL_TAG] = self.emails[0]
        if self._phone_digits:
            mapping[USER_PHONE_TAG] = self._phone_digits[0]
        return mapping


DEFAULT_IDENTITY = UserIdentity(
    USER_FIRST, USER_LAST, USER_FIRST_ALIASES, USER_EMAILS, USER_PHONES, USER_CONTACTS
)

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

# What the regex-only path can still find once the analyzer is off. The secret
# patterns carry over verbatim; EMAIL_ADDRESS and PHONE_NUMBER are re-expressed
# here because Presidio's own recognizers for them are unreachable without
# importing the analyzer, which is the 470 MB we are avoiding. CREDIT_CARD and
# IBAN_CODE are checksum-validated by Presidio and have no honest regex, so
# they are detected only when the analyzer runs.
_EMAIL_RUN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

PATTERN_ONLY_ENTITIES = sorted({row[0] for row in SECRET_PATTERNS}) + [
    "EMAIL_ADDRESS", "PHONE_NUMBER",
]

_SECRET_RULES = [(entity, re.compile(regex)) for entity, _, regex, _ in SECRET_PATTERNS]

_ANALYZER = None
_ANONYMIZER = None


def analyzer_available():
    """Whether this box can run the Presidio + spaCy analyzer at all.

    Checked by module presence, never by importing: `import presidio_analyzer`
    pulls spaCy in behind it and costs ~470 MB before a model is even loaded,
    which is the whole reason a small box turns this off. The web UI uses this
    to decide whether the setting is selectable or shown locked."""
    if not PSEUDONYMIZE_ENABLED:
        return False
    for module in ("presidio_analyzer", "presidio_anonymizer", SPACY_MODEL):
        try:
            if importlib.util.find_spec(module) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True


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
            return _tag_value(params, etype, text)

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


def _tag_value(state, etype, surface):
    """Assign, or reuse, the numbered tag standing in for one non-person value.

    Sole allocator of those tags: the Presidio operator and the regex-only path
    both come through here, so a value carries the same tag whichever path
    found it and the mapping restore() reads is written in one place."""
    assert etype, "tagging needs an entity type"
    key = (etype, surface.lower().strip())
    seen = state["seen"]
    if key not in seen:
        state["counters"][etype] += 1
        tag = f"[{etype}{state['counters'][etype]}]"
        seen[key] = tag
        state["mapping"][tag] = surface
    return seen[key]


def _pseudonymize_patterns(text, state):
    """Mask what regexes alone can find, for accounts running without the
    analyzer. Secrets first, so a key embedded in an address-shaped string is
    tagged as a key rather than half-eaten by the email rule."""
    assert state is not None, "pattern masking needs a state"
    for entity, rx in _SECRET_RULES:
        text = rx.sub(lambda m, e=entity: _tag_value(state, e, m.group(0)), text)
    text = _EMAIL_RUN.sub(lambda m: _tag_value(state, "EMAIL_ADDRESS", m.group(0)), text)

    def phone(m):
        if len(_digits(m.group(0))) < _MIN_PHONE_DIGITS:
            return m.group(0)
        return _tag_value(state, "PHONE_NUMBER", m.group(0))

    return _PHONE_RUN.sub(phone, text)


def new_state(identity=None):
    """Fresh shared mapping for one draft, or None when disabled.

    identity is the account owner whose own name/email get fixed tags; defaults
    to DEFAULT_IDENTITY so single-tenant callers need pass nothing. It also
    carries whether this account runs the analyzer; an account that asked for it
    on a box without it installed gets the regex-only path rather than a crash,
    which is why the flag is resolved here and not at the call site."""
    if not PSEUDONYMIZE_ENABLED:
        return None
    identity = identity or DEFAULT_IDENTITY
    return {
        "account_id": identity.account_id,
        "identity": identity,
        "analyzer": bool(identity.analyzer and analyzer_available()),
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


def _scrub_contacts(text, state):
    """Deterministically tag known contact names before Presidio, so the
    finite set of the owner's contacts is masked even when NER misses them.

    Formatting-variant tolerant (case + internal whitespace). Each contact is
    routed through the same person machinery as NER-detected names, so a contact
    and its later NER mentions collapse to one person id. Single-token contacts
    that collide with a stopword are left alone to avoid nuking common words."""
    for surface in state["identity"].contacts:
        tokens = surface.split()
        if not tokens:
            continue
        pat = re.compile(r"\b" + r"\s+".join(re.escape(t) for t in tokens) + r"\b", re.IGNORECASE)
        if not pat.search(text):
            continue
        if surface.lower() not in state["pindex"]:
            if len(tokens) >= 2:
                _resolve_full(state, surface)
            elif not _stop(surface):
                _resolve_single(state, surface)
        comp = state["pindex"].get(surface.lower())
        if comp:
            text = pat.sub(comp, text)
    return text


def _mask_names(text, state):
    names = state["names"]
    for surface in sorted(names, key=len, reverse=True):
        text = re.sub(rf"\b{re.escape(surface)}\b", names[surface], text)
    return text


def pseudonymize(text, state):
    """Replace PII in text with numbered tags, growing the shared state.

    The owner's own name/email/phone and known contact names are scrubbed
    deterministically before Presidio (literal match, formatting-variant
    tolerant), so the finite highest-stakes set is masked regardless of what NER
    catches. Names seen earlier in the draft are re-masked so a name cannot drift
    to a new tag. Presidio then
    detects any new PII; _resolve_persons groups co-referent name fragments
    under one person id and decomposes each into first/last role tags, so the
    model sees [PERSON1_FIRST] / [PERSON1_LAST] as the same identity.

    With the analyzer off, the deterministic layers above still run and the
    secret, email and phone regexes replace it, so the owner's own identifiers,
    known contacts, and anything key-shaped are still masked. What is lost is
    detection of people, places and organisations this account has never
    corresponded with before.

    Passthrough when disabled or when text is empty.
    """
    if state is None or not text:
        return text

    text = state["identity"].mask_user(text)
    text = _scrub_contacts(text, state)
    text = _mask_names(text, state)
    if not state["analyzer"]:
        return _pseudonymize_patterns(text, state)

    from presidio_anonymizer.entities import OperatorConfig

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
