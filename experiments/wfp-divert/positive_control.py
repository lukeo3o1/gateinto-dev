import argparse
import json
import pathlib
import subprocess
import sys
import time

from run import JsonTail, native_path, normalized_path


def matching_drops(records, selected_path, attempt):
    keys = ['local_port', 'remote_ip', 'remote_port', 'protocol']
    return [r for r in records if r.get('kind') == 'wfp_other'
            and r.get('event_type_name') == 'classify_drop'
            and normalized_path(r.get('app_path', '')) == normalized_path(selected_path)
            and all(r.get(key) == attempt.get(key) for key in keys)
            and r.get('recv_qpc', 0) >= attempt['attempt_qpc']]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        parser.error('--out must be empty to avoid stale control evidence')
    args.out.mkdir(parents=True, exist_ok=True)
    stop = (args.out / 'native.stop').resolve()
    state = (args.out / 'bfe-state.json').resolve()
    events = (args.out / 'native.jsonl').resolve()
    attempt_file = (args.out / 'client-attempt.jsonl').resolve()
    summary = {'status': 'FAIL', 'purpose': 'blocked-flow positive control, never an allow ownership source'}
    process = None
    try:
        with (args.out / 'native.stdout.txt').open('w') as output:
            process = subprocess.Popen([str(args.bin / 'native-events.exe'), '--seconds', '15',
                                        '--out', str(events), '--stop-file', str(stop),
                                        '--state-out', str(state)], stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 8
            ready = False
            while not ready:
                ready = any(r.get('kind') == 'ready' for r in JsonTail(events).read())
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('native positive-control subscriber not ready')
                time.sleep(.02)
            client = subprocess.run([str(args.bin / 'app-b.exe'), '--target', args.target,
                                     '--port', '443', '--protocol', 'tcp', '--nonce', 'blocked-positive-control',
                                     '--connect-only', '1', '--attempt-out', str(attempt_file)],
                                    capture_output=True, text=True, timeout=10)
            (args.out / 'client.stdout.txt').write_text(client.stdout + client.stderr)
            time.sleep(2)
            stop.touch()
            process.wait(timeout=5)
        records = JsonTail(events).read()
        expected = normalized_path(native_path(args.bin / 'app-b.exe'))
        attempts = JsonTail(attempt_file).read()
        if len(attempts) != 1 or attempts[0].get('kind') != 'client_attempt':
            raise RuntimeError('blocked client did not record a successful bind and connect attempt')
        drops = matching_drops(records, expected, attempts[0])
        final = next((r for r in reversed(records) if r.get('kind') == 'summary'), None)
        diagnostic = [dict(event_type=r.get('event_type'), flags=r.get('flags'),
                           app_path_matches=normalized_path(r.get('app_path', '')) == expected,
                           protocol=r.get('protocol'),
                           bound_port_matches=r.get('local_port') == attempts[0]['local_port'])
                      for r in records if r.get('kind') == 'wfp_other']
        summary.update(client_exit=client.returncode, matching_native_drops=len(drops),
                       native_summary=final, diagnostic_events=diagnostic)
        if client.returncode == 0 or not drops or process.returncode != 0 or not final or final.get('errors') or final.get('queue_dropped'):
            raise RuntimeError('blocked connection and native drop notification were not both verified')
        summary['status'] = 'PASS_BLOCKED_EVENT_CONTROL'
    except Exception as error:
        summary['error'] = str(error)
    finally:
        stop.touch()
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
        if process is not None and process.returncode != 0 and state.exists():
            try:
                restore = subprocess.run([str(args.bin / 'native-events.exe'), '--restore-state', str(state),
                                          '--out', str((args.out / 'restore.jsonl').resolve())],
                                         capture_output=True, text=True, timeout=10)
                summary['restore_exit'] = restore.returncode
            except Exception as error:
                summary['restore_error'] = str(error)
        (args.out / 'summary-private.json').write_text(json.dumps(summary, indent=2) + '\n')
    safe = {k: summary[k] for k in ['status', 'purpose', 'client_exit', 'matching_native_drops',
                                    'diagnostic_events', 'restore_exit'] if k in summary}
    counts = summary.get('native_summary') or {}
    safe['native_summary'] = {k: counts[k] for k in ['wfp_count', 'security5156_count', 'queue_dropped', 'errors',
                                                    'wfp_callback_count', 'wfp_drop_count', 'wfp_type_counts'] if k in counts}
    if 'error' in summary:
        safe['failure_reason'] = 'blocked_event_control_not_verified'
    if 'restore_error' in summary:
        safe['restore_failed'] = True
    (args.out / 'summary.json').write_text(json.dumps(safe, indent=2) + '\n')
    print(json.dumps(safe))
    return 0 if summary['status'] == 'PASS_BLOCKED_EVENT_CONTROL' else 1


if __name__ == '__main__':
    sys.exit(main())
