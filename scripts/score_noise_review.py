"""Score the synthetic 500-alert review from recorded exact scopes; not Falco replay."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def score(scenario: Path, session_out: Path):
    truth = json.loads((scenario / 'ground-truth.json').read_text(encoding='utf-8'))
    alerts = [json.loads(line) for line in (scenario / 'alerts.synthetic.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    expected = {r['alert_id']: r['expected_action'] for r in truth['alerts']}
    if len(expected) != len(alerts) or {a['alert_id'] for a in alerts} != set(expected):
        raise ValueError('scenario logs and ground truth disagree')
    session = json.loads((session_out / 'session.json').read_text(encoding='utf-8'))
    accepted = set()
    for decision in session['decisions']:
        if decision.get('decision') in ('a', 'accept'):
            accepted.add(decision['proposal_dir'].replace('\\', '/'))
    results, suppressed = [], set()
    for path in sorted((session_out / 'proposals').glob('*/proposal.json')):
        report = json.loads(path.read_text(encoding='utf-8'))
        scope = report['exception_scope']
        matches = {a['alert_id'] for a in alerts if a['rule'] == report['rule'] and
                   all(a['output_fields'].get(k) == v for k, v in scope.items())}
        noise = sum(expected[i] == 'suppress' for i in matches)
        suspicious = len(matches) - noise
        is_accepted = path.parent.relative_to(session_out).as_posix() in accepted
        if is_accepted:
            suppressed.update(matches)
        results.append({'proposal': str(path.parent.relative_to(session_out)), 'rule': report['rule'],
                        'accepted': is_accepted, 'would_suppress_noise': noise,
                        'would_hide_suspicious': suspicious})
    removed_noise = sum(expected[i] == 'suppress' for i in suppressed)
    hidden_suspicious = len(suppressed) - removed_noise
    return {'measurement': 'synthetic recorded-field projection, NOT runtime replay',
            'input_alerts': len(alerts), 'proposals': results,
            'accepted_projection': {'noise_removed': removed_noise, 'suspicious_hidden': hidden_suspicious,
                                    'alerts_remaining': len(alerts) - len(suppressed),
                                    'suspicious_preserved': truth['expected_preserved'] - hidden_suspicious}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, default=Path('examples/ai-review-500'))
    parser.add_argument('--session-out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(score(args.scenario, args.session_out), indent=2))
