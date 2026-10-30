"""A small Sigma rule engine: TraceForge's detection rules are standard Sigma rules, loaded from YAML.

Sigma (https://github.com/SigmaHQ/sigma-specification) is the open, vendor-neutral format for
detection rules used across SIEMs (Splunk, Elastic, QRadar, Wazuh). Every rule in sigma_rules/ has
the standard fields (title, id, status, description, references, author, date, logsource,
detection, falsepositives, level, tags with MITRE ATT&CK IDs) and one TraceForge extension, `risk`,
its risk assessment under NIST SP 800-30 Rev. 1 (see server/scoring/nist.py):

    likelihood, impact   semi-quantitative values 0-100 (Tables G-4 and H-3), with a rationale
    level of risk        Table I-2 matrix of the two levels
    risk value           likelihood x impact / 100 (ISO/IEC 27005), within the Table I-3 range

The rule's Sigma level must be the one matching its NIST level of risk (Very Low = informational,
Low = low, Moderate = medium, High = high, Very High = critical), so the two never disagree.

Rules match one event: a flat document of fields (see rules.py for what each field means; facts
that need history, such as "this device was recorded as a different type", are computed first and
matched as fields, the way a SIEM enriches events before its rules run).

Supported: named search identifiers (a map is AND, a list of maps is OR, a list of values is OR),
conditions with and / or / not / parentheses / "1 of x*" / "all of x*" / "them", and the value
modifiers gt, gte, lt, lte, contains, startswith, endswith, exists, fieldref and all. Plain string
values compare case-insensitively and accept * and ? wildcards, as in Sigma.
"""

import fnmatch
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from server.scoring import nist

RULES_DIR = Path(__file__).with_name("sigma_rules")
SIGMA_LEVELS = tuple(nist.SIGMA_LEVEL.values())
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
PRODUCT = "traceforge"
# "any" (usb_event) holds rules about the report itself rather than the device, which apply whatever
# kind of event it is (an event dated in the future); they run in addition to the event's own category.
CATEGORIES = {"connect": "usb_connect", "typing": "usb_typing", "disconnect": "usb_disconnect", "any": "usb_event"}
MODIFIERS = {"gt", "gte", "lt", "lte", "contains", "startswith", "endswith", "exists", "fieldref", "all"}
REQUIRED = ("title", "id", "name", "status", "description", "author", "date", "logsource", "detection", "level", "tags", "risk")
TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    title: str
    status: str
    level: str
    description: str
    category: str
    tags: tuple[str, ...]
    likelihood: float
    impact: float
    rationale: str
    falsepositives: tuple[str, ...]
    references: tuple[str, ...]
    path: str
    matches: Callable[[dict], bool] = field(repr=False, compare=False)

    @property
    def risk(self) -> float:
        return nist.risk_value(self.likelihood, self.impact)

    @property
    def risk_level(self) -> str:
        return nist.risk_level(self.likelihood, self.impact)

    @property
    def techniques(self) -> list[str]:
        return [m.group(1).upper() for t in self.tags if (m := TECHNIQUE_TAG.fullmatch(t))]

    def summary(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "title": self.title,
            "status": self.status,
            "level": self.level,
            "description": self.description,
            "event_type": next(k for k, v in CATEGORIES.items() if v == self.category),
            "likelihood": self.likelihood,
            "likelihood_level": nist.level_for(self.likelihood),
            "impact": self.impact,
            "impact_level": nist.level_for(self.impact),
            "risk_level": self.risk_level,
            "risk_score": self.risk,
            "rationale": self.rationale,
            "tags": list(self.tags),
            "falsepositives": list(self.falsepositives),
            "references": list(self.references),
            "file": self.path,
        }


# --- matching -------------------------------------------------------------------------------------


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _compare(actual, expected, mods: list[str]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if isinstance(actual, (list, tuple)):
        return any(_compare(a, expected, mods) for a in actual)
    for op, test in (("gt", float.__gt__), ("gte", float.__ge__), ("lt", float.__lt__), ("lte", float.__le__)):
        if op in mods:
            return _number(actual) and _number(expected) and test(float(actual), float(expected))
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(actual, bool) and isinstance(expected, bool) and actual == expected
    if _number(expected) and _number(actual):
        return actual == expected
    a, e = str(actual).lower(), str(expected).lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    return fnmatch.fnmatchcase(a, e) if any(c in e for c in "*?") else a == e


def _field_matches(key: str, expected, doc: dict) -> bool:
    name, *mods = key.split("|")
    actual = doc.get(name)
    if "exists" in mods:
        return (actual is not None) == bool(expected)
    values = list(expected) if isinstance(expected, list) else [expected]
    if "fieldref" in mods:
        values = [doc.get(v) for v in values]
    combine = all if "all" in mods else any
    return combine(_compare(actual, v, mods) for v in values)


def _search_matches(spec, doc: dict) -> bool:
    if isinstance(spec, list):  # a list of maps: any of them
        return any(_search_matches(s, doc) for s in spec)
    return all(_field_matches(k, v, doc) for k, v in spec.items())


# --- condition parsing ----------------------------------------------------------------------------

TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokens(condition: str) -> list[str]:
    pos, out = 0, []
    while pos < len(condition.rstrip()):
        m = TOKEN.match(condition, pos)
        if m is None:
            raise RuleError(f"cannot parse condition at: {condition[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def _compile_condition(condition: str, searches: dict) -> Callable[[dict], bool]:
    tokens = _tokens(condition)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take(expected=None):
        nonlocal pos
        tok = peek()
        if tok is None or (expected and tok != expected):
            raise RuleError(f"condition {condition!r}: expected {expected or 'a term'}, got {tok!r}")
        pos += 1
        return tok

    def pattern(p: str) -> list[str]:
        names = list(searches) if p == "them" else [n for n in searches if fnmatch.fnmatchcase(n, p)]
        if not names:
            raise RuleError(f"condition {condition!r}: {p!r} matches no search identifier")
        return names

    def factor():
        tok = take()
        if tok == "not":
            inner = factor()
            return lambda d: not inner(d)
        if tok == "(":
            inner = expr()
            take(")")
            return inner
        if tok in ("1", "all") and peek() == "of":
            take("of")
            names = pattern(take())
            combine = any if tok == "1" else all
            return lambda d: combine(_search_matches(searches[n], d) for n in names)
        if tok not in searches:
            raise RuleError(f"condition {condition!r}: unknown search identifier {tok!r}")
        return lambda d: _search_matches(searches[tok], d)

    def term():
        parts = [factor()]
        while peek() == "and":
            take()
            parts.append(factor())
        return parts[0] if len(parts) == 1 else lambda d: all(p(d) for p in parts)

    def expr():
        parts = [term()]
        while peek() == "or":
            take()
            parts.append(term())
        return parts[0] if len(parts) == 1 else lambda d: any(p(d) for p in parts)

    result = expr()
    if peek() is not None:
        raise RuleError(f"condition {condition!r}: unexpected {peek()!r}")
    return result


# --- loading --------------------------------------------------------------------------------------


def _check_search(name: str, spec, where: str) -> None:
    maps = spec if isinstance(spec, list) else [spec]
    if not maps or not all(isinstance(m, dict) and m for m in maps):
        raise RuleError(f"{where}: search {name!r} must be a map or a list of maps")
    for m in maps:
        for key in m:
            unknown = set(key.split("|")[1:]) - MODIFIERS
            if unknown:
                raise RuleError(f"{where}: unsupported modifier(s) {sorted(unknown)} in {key!r}")


def parse_rule(data: dict, where: str) -> Rule:
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise RuleError(f"{where}: missing {', '.join(missing)}")
    try:
        uuid.UUID(str(data["id"]))
    except ValueError:
        raise RuleError(f"{where}: id must be a UUID") from None
    if data["status"] not in STATUSES:
        raise RuleError(f"{where}: unknown status {data['status']!r}")
    if data["level"] not in SIGMA_LEVELS:
        raise RuleError(f"{where}: level must be one of {', '.join(SIGMA_LEVELS)}")
    logsource = data["logsource"] or {}
    if logsource.get("product") != PRODUCT or logsource.get("category") not in CATEGORIES.values():
        raise RuleError(f"{where}: logsource must be product {PRODUCT} with a category in {sorted(CATEGORIES.values())}")

    detection = dict(data["detection"] or {})
    condition = detection.pop("condition", None)
    if not isinstance(condition, str) or not detection:
        raise RuleError(f"{where}: detection needs search identifiers and one condition string")
    for name, spec in detection.items():
        _check_search(name, spec, where)

    risk = data["risk"] or {}
    likelihood, impact, rationale = risk.get("likelihood"), risk.get("impact"), risk.get("rationale")
    if not all(_number(v) and 0 <= v <= 100 for v in (likelihood, impact)):
        raise RuleError(f"{where}: risk needs likelihood and impact between 0 and 100 (NIST SP 800-30)")
    if not isinstance(rationale, str) or not rationale.strip():
        raise RuleError(f"{where}: risk needs a rationale for its likelihood and impact")
    level = nist.risk_level(likelihood, impact)
    if nist.SIGMA_LEVEL[level] != data["level"]:
        raise RuleError(
            f"{where}: NIST SP 800-30 Table I-2 gives {nist.LABELS[level]} risk for likelihood {likelihood:g} and "
            f"impact {impact:g}, which is Sigma level {nist.SIGMA_LEVEL[level]}, not {data['level']}"
        )
    tags = tuple(data["tags"] or ())
    if not any(TECHNIQUE_TAG.fullmatch(t) for t in tags):
        raise RuleError(f"{where}: tags need at least one MITRE ATT&CK technique (attack.tNNNN)")

    return Rule(
        id=str(data["id"]),
        name=data["name"],
        title=data["title"],
        status=data["status"],
        level=data["level"],
        description=" ".join(str(data["description"]).split()),
        category=logsource["category"],
        tags=tags,
        likelihood=float(likelihood),
        impact=float(impact),
        rationale=" ".join(rationale.split()),
        falsepositives=tuple(data.get("falsepositives") or ()),
        references=tuple(data.get("references") or ()),
        path=where,
        matches=_compile_condition(condition, detection),
    )


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    rules = []
    for path in sorted(directory.glob("*.yml")):
        with path.open(encoding="utf-8") as f:
            rules.append(parse_rule(yaml.safe_load(f), f"{directory.name}/{path.name}"))
    for attr in ("id", "name"):
        seen = [getattr(r, attr) for r in rules]
        dupes = sorted({v for v in seen if seen.count(v) > 1})
        if dupes:
            raise RuleError(f"duplicate rule {attr}(s): {', '.join(dupes)}")
    return rules


RULES = load_rules()
BY_NAME = {r.name: r for r in RULES}


def evaluate(event_type: str, doc: dict) -> list[Rule]:
    """Every rule for this kind of event whose detection matches the document, in catalogue order."""
    category = CATEGORIES.get(event_type)
    return [r for r in RULES if r.category == category and r.matches(doc)]
