import pytest

from fwlens.models import Vendor
from fwlens.parsers import parse_config_file
from fwlens.samplegen import SAMPLES


@pytest.mark.parametrize(
    ("path", "vendor"),
    [
        (SAMPLES / "panos" / "lab-fw01.xml", Vendor.PANOS),
        (SAMPLES / "fortigate" / "lab-fgt01.conf", Vendor.FORTIGATE),
    ],
)
def test_vendor_from_extension(path, vendor) -> None:
    assert parse_config_file(path).vendor is vendor


def test_explicit_vendor_overrides_extension(tmp_path) -> None:
    fgt = tmp_path / "backup.txt"
    fgt.write_text((SAMPLES / "fortigate" / "lab-fgt01.conf").read_text())
    assert parse_config_file(fgt, "fortigate").device == "lab-fgt01"


def test_unknown_extension_raises(tmp_path) -> None:
    with pytest.raises(ValueError, match="can't tell the vendor"):
        parse_config_file(tmp_path / "backup.txt")
