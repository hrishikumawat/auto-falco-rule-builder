"""Generate a reproducible synthetic noise lab. Commands are strings, never executed."""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


# label, executable, authorized command, parent, account, unauthorized variation
CASES = [
    ('Health Check', 'curl', 'curl -fsS https://status.example.test/health', 'cron', 'svc-health',
     'curl -fsS https://downloads.example.test/unapproved.sh'),
    ('Artifact Fetch', 'wget', 'wget -q https://artifacts.example.test/releases/app.tar.gz', 'deploy-agent', 'svc-deploy',
     'wget -q https://downloads.example.test/unapproved.sh'),
    ('Maintenance Shell', 'sh', 'sh /opt/ops/rotate-logs.sh', 'cron', 'svc-ops',
     'sh /tmp/unapproved.sh'),
    ('Backup Archive', 'tar', 'tar -czf /var/backups/app.tgz /srv/app/data', 'backup-agent', 'svc-backup',
     'tar -czf /tmp/secrets.tgz /etc/shadow'),
    ('Cache Scan', 'find', 'find /var/cache/app -type f -mtime +7 -print', 'cron', 'svc-cache',
     'find /etc -name shadow -print'),
    ('Deploy Permissions', 'chmod', 'chmod 640 /srv/app/config/runtime.conf', 'deploy-agent', 'svc-deploy',
     'chmod 777 /srv/app/config/runtime.conf'),
    ('Deploy Ownership', 'chown', 'chown app:app /srv/app/releases/current', 'deploy-agent', 'svc-deploy',
     'chown webapp:webapp /etc/shadow'),
    ('Cache Cleanup', 'rm', 'rm -f /var/cache/app/stale.marker', 'cron', 'svc-cache',
     'rm -rf /var/log/audit'),
    ('Metrics Script', 'python3', 'python3 /opt/monitoring/export_metrics.py', 'monitor-agent', 'svc-monitor',
     'python3 /tmp/unapproved.py'),
    ('Port Probe', 'nc', 'nc -z -w 2 db.internal.example.test 5432', 'monitor-agent', 'svc-monitor',
     'nc -l -p 4444'),
]


def generate(out: Path):
    if out.exists():
        raise ValueError(f'output already exists; choose a new directory: {out}')
    rules_dir = out / 'rules'
    rules_dir.mkdir(parents=True)
    entries = [{'macro': 'noise_lab_successful_exec',
                'condition': 'evt.type in (execve, execveat) and evt.rawres >= 0'}]
    alerts, truth, context, summary = [], [], [], []
    start = datetime(2026, 10, 4, 8, tzinfo=timezone.utc)
    for number, (label, proc, command, parent, account, bad_command) in enumerate(CASES, 1):
        name = f'Noise Lab {number:02d} {label}'
        entries.append({'rule': name, 'desc': f'Synthetic broad {proc} execution alert for noise-tuning practice',
                        'condition': f'noise_lab_successful_exec and proc.name = {json.dumps(proc)}',
                        'output': 'Synthetic execution (command=%proc.cmdline parent=%proc.pname user=%user.name)',
                        'priority': 'WARNING', 'tags': ['synthetic', 'noise-lab', 'process']})
        expected_scope = {'proc.cmdline': command, 'proc.pname': parent, 'user.name': account}
        context.append(f'{name}: authorize ONLY command [{command}] with parent [{parent}] and account [{account}].')
        variants = [('authorized_noise', command, parent, account, 40),
                    ('changed_command_same_identity', bad_command, parent, account, 5),
                    ('authorized_command_wrong_account', command, parent, 'webapp', 3),
                    ('authorized_command_wrong_parent', command, 'interactive-shell', account, 2)]
        for kind, cmd, pname, user, count in variants:
            for _ in range(count):
                index = len(alerts) + 1
                alert_id = f'noise-lab-{index:04d}'
                fields = {'evt.type': 'execve', 'evt.rawres': 0, 'proc.name': proc,
                          'proc.cmdline': cmd, 'proc.pname': pname, 'user.name': user}
                alerts.append({'alert_id': alert_id, 'rule': name, 'priority': 'WARNING', 'source': 'syscall',
                               'tags': ['synthetic', 'noise-lab'],
                               'output': f'Synthetic execution (command={cmd} parent={pname} user={user})',
                               'output_fields': fields})
                truth.append({'alert_id': alert_id, 'rule': name, 'kind': kind,
                              'expected_action': 'suppress' if kind == 'authorized_noise' else 'preserve'})
        summary.append({'rule': name, 'alerts': 50, 'authorized_noise': 40, 'preserve': 10,
                        'expected_exception_scope': expected_scope})
    # Avoid presenting authorized groups first in every rule; order is reproducible.
    random.Random(1729).shuffle(alerts)
    for index, alert in enumerate(alerts):
        alert['time'] = (start + timedelta(seconds=index * 10)).isoformat().replace('+00:00', 'Z')
    (rules_dir / 'rules.yaml').write_text('# SYNTHETIC LAB: all ten rules are intentionally noisy.\n' +
                                        yaml.safe_dump(entries, sort_keys=False), encoding='utf-8', newline='\n')
    (out / 'alerts.synthetic.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in alerts), encoding='utf-8', newline='\n')
    context.insert(0, 'Synthetic lab authorization policy. All activity not explicitly authorized below must remain detectable. Frequency alone does not establish authorization.')
    (out / 'context.txt').write_text('\n'.join(context) + '\n', encoding='utf-8', newline='\n')
    profile = json.loads((Path(__file__).resolve().parents[1] / 'examples/ai-review/lab.profile.json').read_text(encoding='utf-8'))
    profile['name'] = 'Synthetic 500-alert noise lab; not a production profile'
    (out / 'lab.profile.json').write_text(json.dumps(profile, indent=2) + '\n', encoding='utf-8', newline='\n')
    oracle = {'synthetic': True, 'seed': 1729, 'total_alerts': 500, 'rule_count': 10,
              'expected_suppressed': 400, 'expected_preserved': 100, 'rules': summary, 'alerts': truth}
    (out / 'ground-truth.json').write_text(json.dumps(oracle, indent=2) + '\n', encoding='utf-8', newline='\n')
    # Verify the oracle against values in the actual generated input, independently of the AI.
    by_id = {a['alert_id']: a for a in alerts}
    scopes = {r['rule']: r['expected_exception_scope'] for r in summary}
    counts = Counter(a['rule'] for a in alerts)
    if len(alerts) != 500 or len(counts) != 10 or set(counts.values()) != {50}:
        raise ValueError('unexpected fixture counts')
    for expected in truth:
        actual = by_id[expected['alert_id']]
        covered = all(actual['output_fields'].get(k) == v for k, v in scopes[actual['rule']].items())
        if covered != (expected['expected_action'] == 'suppress'):
            raise ValueError('oracle does not match generated evidence')
    if len('\n'.join(context)) > 4000:
        raise ValueError('context exceeds CLI limit')
    print(json.dumps({'out': str(out.resolve()), 'rules': 10, 'alerts': 500,
                      'noise': 400, 'preserve': 100, 'synthetic': True}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('examples/ai-review-500'))
    generate(parser.parse_args().out)
