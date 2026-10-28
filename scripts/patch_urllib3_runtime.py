"""Replay the reviewed upstream response-framing correction on pinned urllib3."""
import importlib.metadata
import json
from pathlib import Path
import sysconfig

from patch_python_runtime import apply_patches


def main():
    if importlib.metadata.version('urllib3') != '2.8.0':
        raise RuntimeError('Unreviewed urllib3 version')
    patches = json.loads(Path(__file__).with_name('urllib3_security_patches.json').read_text())
    lock = json.loads(Path(__file__).with_name('http_framing_sources.json').read_text())
    for record in apply_patches(Path(sysconfig.get_path('purelib')), patches,
            final_hashes={'urllib3/response.py': lock['urllib3.response']['after_sha256']}):
        print(json.dumps(record))


if __name__ == '__main__':
    main()
