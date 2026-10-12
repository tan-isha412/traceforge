"""MITRE ATT&CK techniques for each finding, so an investigator sees the attack behaviour behind it.

Only findings with a clear technique are mapped; behavioural ML findings are left unmapped because
an unusual pattern alone does not say which technique (if any) is in play.
"""

TECHNIQUES = {
    "T1200": ("Hardware Additions", "Initial Access"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1091": ("Replication Through Removable Media", "Lateral Movement"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1052.001": ("Exfiltration over USB", "Exfiltration"),
}

FINDING_TECHNIQUES = {
    "unknown_device": ["T1200"],
    "device_type_mismatch": ["T1200", "T1036", "T1059"],  # a "drive" that types: keystroke injection
    "serial_reuse_across_models": ["T1200", "T1036"],
    "serial_format_mismatch": ["T1200", "T1036"],
    "missing_serial": ["T1200"],
    "same_model_new_serial": ["T1200", "T1036"],
    "descriptor_mismatch": ["T1200", "T1036"],
    "descriptor_model_mismatch": ["T1200", "T1036"],
    "programmable_hid_board": ["T1200", "T1059"],
    "keystroke_injection": ["T1200", "T1059"],
    "large_transfer": ["T1052.001"],
    "blocklisted_device": ["T1200"],
    "new_source_machine": ["T1091"],
}


def technique(tid: str) -> dict:
    name, tactic = TECHNIQUES[tid]
    return {"id": tid, "name": name, "tactic": tactic, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


def techniques_for(finding_name: str) -> list[dict]:
    return [technique(t) for t in FINDING_TECHNIQUES.get(finding_name, [])]


def techniques_for_all(finding_names, cross_machine: bool = False) -> list[dict]:
    """Distinct techniques for a set of findings, in a stable order; a cross-machine case adds T1091."""
    ids = []
    for name in finding_names:
        ids += FINDING_TECHNIQUES.get(name, [])
    if cross_machine:
        ids.append("T1091")
    return [technique(t) for t in sorted(set(ids), key=list(TECHNIQUES).index)]
