import argparse
import json
import pathlib


CASE_NAMES = ("tcp-control", "udp-control", "tcp-live", "udp-live", "tcp-short", "udp-short", "tcp-burst", "udp-burst")


def aggregate(root):
    from socket_probe import socket_public_summary

    cases = []
    missing = unreadable = available = 0
    for name in CASE_NAMES:
        path = pathlib.Path(root) / name / "public-summary.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            missing += 1
            summary = dict(status="MISSING_SUMMARY")
        except (OSError, ValueError):
            unreadable += 1
            summary = dict(status="INVALID_SUMMARY")
        else:
            available += 1
            summary = socket_public_summary(value)
        cases.append(dict(case=name, summary=summary))
    return dict(schema_version=1, available_cases=available, missing_cases=missing,
                unreadable_cases=unreadable, cases=cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = aggregate(args.root)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return int(bool(result["missing_cases"] or result["unreadable_cases"]))


if __name__ == "__main__":
    raise SystemExit(main())
