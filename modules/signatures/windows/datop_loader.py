# Copyright (C) 2021 bartblaze
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


class DatopLoader(Signature):
    name = "datop_loader"
    description = "Exhibits indicators of DatopLoader, loader often used by Qakbot."
    severity = 3
    families = ["Datop"]
    categories = ["loader"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True

    def run(self):
        indicators = (r"[A-Z]:\\Datop\\.*",)

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
