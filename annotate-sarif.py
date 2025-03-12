#!/usr/bin/env python

import json
import logging
import sys

CVSS_SCORE_MAP = {
    "low": "2.0",
    "medium": "5.0",
    "high": "8.0",
    "critical": "9.5",
}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    input_io = open(sys.argv[1], "r") if len(sys.argv) > 1 else sys.stdin
    doc = json.load(input_io)
    for run in doc["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            if "properties" in rule and "security" in rule["properties"]["tags"]:
                for severity, value in CVSS_SCORE_MAP.items():
                    if severity.upper() in rule["properties"]["tags"]:
                        rule["properties"]["security-severity"] = value
                        break
                if "security-severity" not in rule["properties"]:
                    logger.error(
                        "Could not find a CVSS score for rule %s", rule["id"]
                    )
            logger.info(
                "Adding security-severity property %s to rule %s",
                rule["properties"]["security-severity"],
                rule["id"],
            )

    print(json.dumps(doc, indent=2))
