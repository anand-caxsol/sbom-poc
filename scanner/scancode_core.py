"""Core ScanCode normalization, correlation, and policy evaluation."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_POLICY = {
    "restricted_licenses": ["AGPL", "GPL"],
    "review_licenses": ["LGPL", "SSPL", "BUSL", "CC-BY-NC"],
    "unknown_license_patterns": ["unknown", "proprietary", "commercial"],
    "fail_on_conflict": True,
    "fail_on_scan_error": True,
}

REPORT_NOTICE = (
    "Source-level evidence only. This report does not prove which files or "
    "components were compiled into a final binary, firmware, container, or image."
)


def merge_policy(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = dict(DEFAULT_POLICY)
    if overrides:
        policy.update(overrides)
    for key in (
        "restricted_licenses",
        "review_licenses",
        "unknown_license_patterns",
    ):
        value = policy.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"Policy field '{key}' must be a list of strings")
    return policy


def unique_strings(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        identity = text.casefold()
        if text and identity not in seen:
            seen.add(identity)
            result.append(text)
    return result


def license_expressions(resource: dict[str, Any]) -> list[str]:
    expressions: list[Any] = [
        resource.get("detected_license_expression_spdx"),
        resource.get("detected_license_expression"),
    ]
    for detection in resource.get("license_detections") or []:
        expressions.extend(
            [
                detection.get("license_expression_spdx"),
                detection.get("license_expression"),
            ]
        )
    for license_match in resource.get("licenses") or []:
        expressions.extend(
            [
                license_match.get("spdx_license_key"),
                license_match.get("key"),
            ]
        )
    return unique_strings(expressions)


def flattened_values(resource: dict[str, Any], field: str, key: str) -> list[str]:
    return unique_strings(
        item.get(key) for item in resource.get(field) or [] if isinstance(item, dict)
    )


def package_index(scan: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for package in scan.get("packages") or []:
        if not isinstance(package, dict):
            continue
        name = package.get("name") or package.get("purl") or "unnamed-package"
        version = package.get("version")
        label = f"{name}@{version}" if version else str(name)
        for identity in (package.get("package_uid"), package.get("purl")):
            if identity:
                result[str(identity)] = label
    return result


def component_for(resource: dict[str, Any], packages: dict[str, str]) -> str:
    linked = resource.get("for_packages") or []
    labels = unique_strings(packages.get(str(item), item) for item in linked)
    if labels:
        return ", ".join(labels)
    parts = Path(str(resource.get("path", ""))).parts
    return parts[0] if len(parts) > 1 else "(repository root)"


def token_matches(expression: str, token: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])"
    return re.search(pattern, expression, flags=re.IGNORECASE) is not None


def classify(
    expressions: list[str],
    errors: list[str],
    policy: dict[str, Any],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    status = "pass"

    restricted = unique_strings(
        token
        for expression in expressions
        for token in policy["restricted_licenses"]
        if token_matches(expression, token)
    )
    review = unique_strings(
        token
        for expression in expressions
        for token in policy["review_licenses"]
        if token_matches(expression, token)
    )
    unknown = unique_strings(
        expression
        for expression in expressions
        if any(
            pattern.casefold() in expression.casefold()
            for pattern in policy["unknown_license_patterns"]
        )
    )

    if restricted:
        status = "fail"
        reasons.append("restricted license: " + ", ".join(restricted))
    if review:
        status = "review" if status == "pass" else status
        reasons.append("manual review license: " + ", ".join(review))
    if unknown:
        status = "review" if status == "pass" else status
        reasons.append("unknown/proprietary expression: " + ", ".join(unknown))
    if len(expressions) > 1:
        reasons.append("multiple license expressions require correlation")
        if policy.get("fail_on_conflict", True):
            status = "fail"
        elif status == "pass":
            status = "review"
    if errors:
        reasons.append("ScanCode reported scan errors")
        if policy.get("fail_on_scan_error", True):
            status = "fail"
        elif status == "pass":
            status = "review"
    return status, reasons


def normalize_scan(scan: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    packages = package_index(scan)
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    for resource in scan.get("files") or []:
        if not isinstance(resource, dict) or resource.get("type") == "directory":
            continue
        scanned_files += 1
        expressions = license_expressions(resource)
        errors = unique_strings(resource.get("scan_errors") or [])
        status, reasons = classify(expressions, errors, policy)
        has_evidence = bool(
            expressions
            or errors
            or resource.get("copyrights")
            or resource.get("holders")
            or resource.get("for_packages")
        )
        if not has_evidence:
            continue
        findings.append(
            {
                "path": str(resource.get("path", "")),
                "component": component_for(resource, packages),
                "license_expressions": expressions,
                "copyrights": flattened_values(
                    resource, "copyrights", "copyright"
                ),
                "holders": flattened_values(resource, "holders", "holder"),
                "package_refs": unique_strings(resource.get("for_packages") or []),
                "scan_errors": errors,
                "status": status,
                "reasons": reasons,
            }
        )

    components: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        grouped[finding["component"]].append(finding)
    for component, items in sorted(grouped.items()):
        status_counts = Counter(item["status"] for item in items)
        expressions = unique_strings(
            expression
            for item in items
            for expression in item["license_expressions"]
        )
        components[component] = {
            "files_with_evidence": len(items),
            "licenses": expressions,
            "pass": status_counts["pass"],
            "review": status_counts["review"],
            "fail": status_counts["fail"],
        }

    status_counts = Counter(item["status"] for item in findings)
    if status_counts["fail"]:
        gate = "fail"
    elif status_counts["review"]:
        gate = "review"
    else:
        gate = "pass"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "notice": REPORT_NOTICE,
        "gate": gate,
        "counts": {
            "scanned_files": scanned_files,
            "files_with_evidence": len(findings),
            "components": len(components),
            "pass": status_counts["pass"],
            "review": status_counts["review"],
            "fail": status_counts["fail"],
        },
        "components": components,
        "findings": sorted(findings, key=lambda item: (item["status"], item["path"])),
    }
