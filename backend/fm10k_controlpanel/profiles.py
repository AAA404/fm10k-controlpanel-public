"""Known board inputs, separate from native runtime and traffic qualification."""
from dataclasses import dataclass


@dataclass(frozen=True)
class BoardProfile:
    family: str
    netfab_hw_version: int
    reference: str
    sha256: str


PROFILES = {
    "sil001-hw4-b0": BoardProfile(
        "B0", 4, "hardware/sdk/platforms/sil001-hw4-b0.cfg",
        "38c481b5d8035df14bc517735cd8e1c1ba9936fdc512fd18c849878fe323da98"),
    # The factory A11h SDK platform name is ALSO sil001. sil006.conf is the
    # separate NetFab service configuration with hw_version=5.
    "sil001-hw5-a11": BoardProfile(
        "A11", 5, "hardware/sdk/platforms/sil001-hw5-a11.cfg",
        "8f5c1700c48984d539ff526f4a4ba18c814db27282de2afe33c90a2888c87d96"),
}
