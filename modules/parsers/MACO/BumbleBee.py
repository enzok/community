from cape_parsers.CAPE.core.BumbleBee import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="BumbleBee", other=raw_config)

    # Campaign ID
    if raw_config.get("Campaign ID"):
        parsed_result.campaign_id.append(raw_config["Campaign ID"])

    # Botnet ID
    if raw_config.get("Botnet ID"):
        parsed_result.identifier.append(raw_config["Botnet ID"])

    # C2s
    for c2 in raw_config.get("C2s", []):
        parsed_result.http.append(MACOModel.Http(hostname=c2, usage="c2"))

    # Data
    if raw_config.get("Data"):
        parsed_result.binaries.append(MACOModel.Binary(data=raw_config["Data"]))

    # RC4 Key
    if raw_config.get("RC4 Key"):
        parsed_result.encryption.append(MACOModel.Encryption(algorithm="rc4", key=raw_config["RC4 Key"]))

    return parsed_result


class BumbleBee(Extractor):
    author = "kevoreilly"
    family = "BumbleBee"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
