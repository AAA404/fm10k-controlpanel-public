#!/usr/bin/env python3
"""Convert an explicitly supplied reference header into the pinned RAM image."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]

def convert(source: bytes, manifest: dict) -> bytes:
    if hashlib.sha256(source).hexdigest() != manifest['source_sha256']:
        raise ValueError('Reference firmware header SHA-256 does not match')
    body = source.decode('ascii').split('= {', 1)[1].split('}', 1)[0]
    words = [int(word, 16) for word in re.findall(r'0x([0-9a-fA-F]+)', body)]
    if len(words) != 4968 or any(word > 1023 for word in words):
        raise ValueError('Invalid reference firmware words')
    binary = struct.pack('<' + 'H' * len(words), *words)
    if hashlib.sha256(binary).hexdigest() != manifest['binary_sha256']:
        raise ValueError('Converted firmware SHA-256 does not match')
    return binary

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/eye-firmware/sbus-master-101a.bin')
    args = parser.parse_args()
    manifest = json.loads((ROOT/'hardware/eye-firmware.json').read_text())
    binary = convert(args.input.read_bytes(), manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(binary)
    print(json.dumps({'file': str(args.output.resolve()), 'bytes': len(binary),
                      'sha256': hashlib.sha256(binary).hexdigest()}))

if __name__ == '__main__':
    main()
