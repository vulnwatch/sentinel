"""Fail when a Renovate JSON lookup log contains package warnings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

PACKAGE_FILES_MESSAGE = "packageFiles with updates"


class RenovateLogValidationError(ValueError):
    """Raised when a Renovate log cannot be validated safely."""


def _read_json_record(line: str, line_number: int) -> dict[str, Any]:
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RenovateLogValidationError(
            f"line {line_number} is not valid JSON: {exc.msg}"
        ) from exc
    if not isinstance(record, dict):
        raise RenovateLogValidationError(
            f"line {line_number} must contain a JSON object"
        )
    return record


def find_package_warnings(stream: TextIO) -> list[str]:
    """Return formatted package warnings from Renovate's lookup summary."""
    summaries = 0
    warnings: list[str] = []

    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        record = _read_json_record(line, line_number)
        if record.get("msg") != PACKAGE_FILES_MESSAGE:
            continue

        summaries += 1
        config = record.get("config")
        if not isinstance(config, dict):
            raise RenovateLogValidationError(
                f"line {line_number} has no package-file configuration object"
            )

        for manager, package_files in config.items():
            if not isinstance(package_files, list):
                raise RenovateLogValidationError(
                    f"line {line_number} manager {manager!r} must contain a list"
                )
            for package_file in package_files:
                if not isinstance(package_file, dict):
                    raise RenovateLogValidationError(
                        f"line {line_number} manager {manager!r} has an invalid entry"
                    )
                file_name = package_file.get("packageFile", "<unknown file>")
                dependencies = package_file.get("deps")
                if not isinstance(dependencies, list):
                    raise RenovateLogValidationError(
                        f"line {line_number} package file {file_name!r} "
                        "has no deps list"
                    )

                for dependency in dependencies:
                    if not isinstance(dependency, dict):
                        raise RenovateLogValidationError(
                            f"line {line_number} package file {file_name!r} "
                            "has an invalid dependency"
                        )
                    package_name = dependency.get(
                        "packageName", dependency.get("depName", "<unknown package>")
                    )
                    datasource = dependency.get("datasource", "unknown datasource")
                    dependency_warnings = dependency.get("warnings", [])
                    if not isinstance(dependency_warnings, list):
                        raise RenovateLogValidationError(
                            f"line {line_number} package {package_name!r} "
                            "has no warnings list"
                        )
                    for warning in dependency_warnings:
                        if not isinstance(warning, dict) or not isinstance(
                            warning.get("message"), str
                        ):
                            raise RenovateLogValidationError(
                                f"line {line_number} package {package_name!r} "
                                "has an invalid warning"
                            )
                        warnings.append(
                            f"{file_name}: {warning['message']} "
                            f"({datasource} package {package_name})"
                        )

    if summaries == 0:
        raise RenovateLogValidationError(
            f"log does not contain the {PACKAGE_FILES_MESSAGE!r} summary"
        )
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Renovate debug log in NDJSON format")
    args = parser.parse_args()

    try:
        with args.log.open(encoding="utf-8") as stream:
            warnings = find_package_warnings(stream)
    except (OSError, RenovateLogValidationError) as exc:
        print(f"Cannot validate Renovate lookup log: {exc}", file=sys.stderr)
        return 2

    if warnings:
        print("Renovate package lookup warnings found:", file=sys.stderr)
        for warning in warnings:
            print(f"- {warning}", file=sys.stderr)
        return 1

    print("Renovate lookup completed without package warnings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
