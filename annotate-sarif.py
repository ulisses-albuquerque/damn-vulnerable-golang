#!/usr/bin/env python

# CVSS SCORE RANGE	SEVERITY IN ADVISORY
# 9.0 - 10.0	Critical
# 7.0 - 8.9	    High
# 4.0 - 6.9     Medium
# 0.1 - 3.9     Low

import json
import logging
import sys

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    input_io = open(sys.argv[1], "r") if len(sys.argv) > 1 else sys.stdin
    doc = json.load(input_io)
    for run in doc.get("runs"):
        for rule in run.get("tool").get("driver").get("rules"):
            if "properties" in rule and "security" in rule.get("properties").get(
                "tags"
            ):
                if "LOW" in rule.get("properties").get("tags"):
                    rule["properties"]["@severity"] = 2.0
                elif "MEDIUM" in rule.get("properties").get("tags"):
                    rule["properties"]["@severity"] = 5.0
                elif "HIGH" in rule.get("properties").get("tags"):
                    rule["properties"]["@severity"] = 8.0
                elif "CRITICAL" in rule.get("properties").get("tags"):
                    rule["properties"]["@severity"] = 9.5

    print(json.dumps(doc, indent=2))
