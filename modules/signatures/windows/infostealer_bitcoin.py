# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class BitcoinWallet(Signature):
    name = "infostealer_bitcoin"
    description = "Attempts to access Bitcoin/ALTCoin wallets"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"
    ttps = ["T1005"]  # MITRE v6,7,8
    mbcs = ["OB0003", "B0028", "B0028.001"]

    def run(self):
        indicators = (
            r".*\\wallet\.dat$",
            r".*\\Bitcoin\\.*",
            r".*\\Electrum\\.*",
            r".*\\MultiBit\\.*",
            r".*\\Litecoin\\.*",
            r".*\\Namecoin\\.*",
            r".*\\Terracoin\\.*",
            r".*\\PPCoin\\.*",
            r".*\\Primecoin\\.*",
            r".*\\Feathercoin\\.*",
            r".*\\Novacoin\\.*",
            r".*\\Freicoin\\.*",
            r".*\\Devcoin\\.*",
            r".*\\Franko\\.*",
            r".*\\ProtoShares\\.*",
            r".*\\Megacoin\\.*",
            r".*\\Quarkcoin\\.*",
            r".*\\Worldcoin\\.*",
            r".*\\Infinitecoin\\.*",
            r".*\\Ixcoin\\.*",
            r".*\\Anoncoin\\.*",
            r".*\\BBQcoin\\.*",
            r".*\\Digitalcoin\\.*",
            r".*\\Mincoin\\.*",
            r".*\\GoldCoin\\ \(GLD\)\\.*",
            r".*\\Yacoin\\.*",
            r".*\\Zetacoin\\.*",
            r".*\\Fastcoin\\.*",
            r".*\\I0coin\\.*",
            r".*\\Tagcoin\\.*",
            r".*\\Bytecoin\\.*",
            r".*\\Florincoin\\.*",
            r".*\\Phoenixcoin\\.*",
            r".*\\Luckycoin\\.*",
            r".*\\Craftcoin\\.*",
            r".*\\Junkcoin\\.*",
        )
        found_match = False

        for indicator in indicators:
            file_matches = self.check_file(pattern=indicator, regex=True, all=True)
            if file_matches:
                for match in file_matches:
                    self.data.append({"file": match})
                    found_match = True
                self.weight += len(file_matches)

        return found_match
