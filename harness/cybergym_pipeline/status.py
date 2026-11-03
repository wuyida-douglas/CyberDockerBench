"""Read-only summary of CyberGym preparation, attempts and grading evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    rows = []
    for state in sorted(args.root.glob('**/pipeline-state.json')):
        try:
            data = json.loads(state.read_text())
            grade = state.parent / 'grade' / 'result.json'
            if grade.is_file():
                data['grade'] = json.loads(grade.read_text())
            data['result_root'] = str(state.parent)
            rows.append(data)
        except (OSError, json.JSONDecodeError) as exc:
            rows.append({'result_root': str(state.parent), 'state': 'invalid_state', 'error': str(exc)})
    summary = {'attempts': len(rows), 'reward_1': sum(row.get('grade', {}).get('reward') == 1 for row in rows),
               'states': {}, 'results': rows}
    for row in rows:
        summary['states'][row['state']] = summary['states'].get(row['state'], 0) + 1
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(f"attempts={summary['attempts']} reward_1={summary['reward_1']} states={summary['states']}")
        for row in rows:
            grade = row.get('grade', {})
            print(f"{row.get('task_id', '?')}: {row['state']} reward={grade.get('reward', '-')} "
                  f"failure_stage={grade.get('failure_stage', '-')} root={row['result_root']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
