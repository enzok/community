# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class StealthWebHistory(Signature):
    name = "stealth_webhistory"
    description = "Clears web history"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1070"]  # MITRE v6,7,8

    def run(self):
        file_indicators = [
            r".*\\History\\History\.IE5\\.*",
            r".*\\Temporary\\ Internet\\ Files\\Content\.IE5\\.*",
        ]
        if self.results.get("target", {}).get("category", "") == "file":
            file_indicators.append(r".*\\Cookies\\.*")
        found_cleaner = False
        for indicator in file_indicators:
            file_match = self.check_delete_file(pattern=indicator, regex=True, all=True)
            if file_match and len(file_match) > 10:
                for match in file_match:
                    self.data.append({"file": match})
                found_cleaner = True
        return found_cleaner
