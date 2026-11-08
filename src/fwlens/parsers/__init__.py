"""Vendor config parsers. parse_config_file() picks one by vendor or file extension."""

from pathlib import Path

from fwlens.models import ParsedConfig, Vendor
from fwlens.parsers.fortigate import parse_fortigate_file
from fwlens.parsers.panos import parse_panos_file

_BY_SUFFIX = {".xml": Vendor.PANOS, ".conf": Vendor.FORTIGATE}


def parse_config_file(path: str | Path, vendor: Vendor | str | None = None) -> ParsedConfig:
    path = Path(path)
    if vendor is None:
        vendor = _BY_SUFFIX.get(path.suffix.lower())
        if vendor is None:
            raise ValueError(f"can't tell the vendor of {path.name}; pass vendor explicitly")
    match Vendor(vendor):
        case Vendor.PANOS:
            return parse_panos_file(path)
        case Vendor.FORTIGATE:
            return parse_fortigate_file(path)
