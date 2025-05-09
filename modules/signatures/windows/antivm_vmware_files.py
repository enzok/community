# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class VMwareDetectFiles(Signature):
    name = "antivm_vmware_files"
    description = "Detects VMware through the presence of a file"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1057", "T1083", "T1497"]  # MITRE v6,7,8
    ttps += ["U1333"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.001", "OB0007", "E1083"]

    def run(self):
        indicators = [
            r".*\\drivers\\vmmouse\.sys$",
            r".*\\drivers\\vmhgfs\.sys$",
            r".*\\vmguestlib\.dll$",
            r".*\\VMware\\ Tools\\TPAutoConnSvc\.exe$",
            r".*\\VMware\\ Tools\\TPAutoConnSvc\.exe\.dll$",
            r".*\\Program\\ Files(\\ \(x86\))?\\VMware\\VMware\\ Tools.*",
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
