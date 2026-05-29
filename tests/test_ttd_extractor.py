"""Quick parity check for the TTD dynamic backend.

Loads a neutral TTD report through TtdExtractor and dumps every feature per scope,
so we can eyeball that calls produce the expected API / Number / String features.
"""
import sys
import json
from pathlib import Path

import capa.helpers
from capa.features.extractors.ttd.extractor import TtdExtractor


def main(path: str) -> int:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    extractor = TtdExtractor.from_report(report)

    print("== detected format ==")
    print(" ", capa.helpers.get_format_from_report(Path(path)))

    print("== global ==")
    for feat, addr in extractor.extract_global_features():
        print(f"  {feat} @ {addr}")

    print("== file ==")
    for feat, addr in extractor.extract_file_features():
        print(f"  {feat} @ {addr}")

    for ph in extractor.get_processes():
        print(f"== process {extractor.get_process_name(ph)} {ph.address} ==")
        for feat, addr in extractor.extract_process_features(ph):
            print(f"  {feat} @ {addr}")

        for th in extractor.get_threads(ph):
            print(f"  -- thread {th.address} --")
            for ch in extractor.get_calls(ph, th):
                print(f"    call: {extractor.get_call_name(ph, th, ch)}")
                for feat, addr in extractor.extract_call_features(ph, th, ch):
                    print(f"      {feat} @ {addr}")

    return 0


if __name__ == "__main__":
    default = str(Path(__file__).resolve().parent / "sample.ttd.json")
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else default))
