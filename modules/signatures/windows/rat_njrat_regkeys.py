# Copyright (C) 2019 ditekshen
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


class NjratRegkeys(Signature):
    name = "njrat_regkeys"
    description = "Creates known Njrat/Bladabindi RAT registry keys"
    severity = 3
    categories = ["rat"]
    families = ["Njrat", "Bladabindi"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1112", "T1219"]  # MITRE v6,7,8
    mbcs = ["B0022", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        njrat_keys = False

        indicators = (
            r"HKEY_CURRENT_USER\\di$",
            r"HKEY_CURRENT_USER\\.*\\\[kl\]$",
        )

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                njrat_keys = True

        return njrat_keys
