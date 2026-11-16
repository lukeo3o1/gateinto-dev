import argparse
import json
import pathlib

from run import public_summary


def aggregate(root, exclude=None):
    cases = []
    unreadable = 0
    for path in sorted(pathlib.Path(root).rglob("summary.json")):
        if exclude is not None and path.resolve() == pathlib.Path(exclude).resolve():
            continue
        try:
            summary = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            unreadable += 1
            summary = {}
        cases.append(public_summary(summary))
    return dict(schema_version=1, case_count=len(cases), unreadable_cases=unreadable, cases=cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()
    result = aggregate(args.root, exclude=args.out)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
