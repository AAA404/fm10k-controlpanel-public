#!/usr/bin/env python3
"""Import an operator-supplied platform file after checking its locked digest."""
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.profiles import PROFILES


def import_platform(profile: str, source: Path, root: Path = ROOT) -> Path:
    spec = PROFILES[profile]
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != spec.sha256:
        raise ValueError(f"platform digest does not match {profile}; inputs cannot be interchanged")
    destination = root / spec.reference
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != data:
            raise ValueError("destination already exists with different content; refusing to replace it")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--input", type=Path, required=True,
                        help="original platform file that you are entitled to use")
    args = parser.parse_args()
    try:
        destination = import_platform(args.profile, args.input)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(destination)


if __name__ == "__main__":
    main()
