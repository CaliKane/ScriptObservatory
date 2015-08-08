#!/usr/bin/env python3
#

import sys
from backend.tasks import yara_retroscan_for_rule

rule_id = int(sys.argv[1])
yara_retroscan_for_rule(rule_id)

