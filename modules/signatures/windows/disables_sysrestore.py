# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesSystemRestore(Signature):
    name = "disables_system_restore"
    description = "Attempts to disable System Restore"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1112", "T1490"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        keys = (
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\ NT\\CurrentVersion\\SystemRestore\\DisableSR$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Policies\\Microsoft\\Windows\\ NT\\SystemRestore\\DisableSR$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Policies\\Microsoft\\Windows\\ NT\\SystemRestore\\DisableConfig$",
        )
        for check in keys:
            if self.check_write_key(pattern=check, regex=True):
                return True

        return False
