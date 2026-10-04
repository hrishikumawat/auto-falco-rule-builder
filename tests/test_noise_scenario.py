import json
from collections import Counter

import pytest
import yaml

from scripts.generate_noise_scenario import generate
from scripts.score_noise_review import score


def test_generator_produces_reproducible_raw_alerts_and_ten_matching_rules(tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    generate(first); generate(second)
    for p in first.rglob('*'):
        if p.is_file():
            assert p.read_bytes() == (second / p.relative_to(first)).read_bytes()
    alerts = [json.loads(line) for line in (first / 'alerts.synthetic.jsonl').read_text().splitlines()]
    rules = [r for r in yaml.safe_load((first / 'rules/rules.yaml').read_text()) if 'rule' in r]
    assert len(alerts) == 500 and len(rules) == 10
    counts = Counter(a['rule'] for a in alerts)
    assert set(counts) == {r['rule'] for r in rules}
    assert set(counts.values()) == {50}
    for a in alerts:
        assert not {'classification', 'exception_scope', 'must_detect'} & set(a)
        rule = next(r for r in rules if r['rule'] == a['rule'])
        assert rule['condition'].endswith('proc.name = ' + json.dumps(a['output_fields']['proc.name']))
    with pytest.raises(ValueError, match='already exists'):
        generate(first)


@pytest.mark.parametrize('wrong_first', [False, True])
def test_scorer_measures_accepted_noise_and_hidden_suspicious_activity(tmp_path, wrong_first):
    scenario, session_out = tmp_path / 'scenario', tmp_path / 'session'
    generate(scenario)
    truth = json.loads((scenario / 'ground-truth.json').read_text())
    alerts = [json.loads(line) for line in (scenario / 'alerts.synthetic.jsonl').read_text().splitlines()]
    decisions = []
    for i, rule in enumerate(truth['rules'], 1):
        scope = rule['expected_exception_scope'].copy()
        if i == 1 and wrong_first:
            sample = next(a for a in alerts if a['rule'] == rule['rule'] and 'unapproved.sh' in a['output_fields']['proc.cmdline'])
            scope['proc.cmdline'] = sample['output_fields']['proc.cmdline']
        path = session_out / 'proposals' / f'{i:03d}'
        path.mkdir(parents=True)
        (path / 'proposal.json').write_text(json.dumps({'rule': rule['rule'], 'exception_scope': scope}))
        decisions.append({'decision': 'a', 'proposal_dir': f'proposals\\{i:03d}'})
    (session_out / 'session.json').write_text(json.dumps({'decisions': decisions}))
    result = score(scenario, session_out)['accepted_projection']
    assert result == ({'noise_removed': 360, 'suspicious_hidden': 5, 'alerts_remaining': 135, 'suspicious_preserved': 95}
                      if wrong_first else {'noise_removed': 400, 'suspicious_hidden': 0, 'alerts_remaining': 100, 'suspicious_preserved': 100})
    (session_out / 'session.json').write_text(json.dumps({'decisions': [{**d, 'decision': 'r'} for d in decisions]}))
    assert score(scenario, session_out)['accepted_projection']['alerts_remaining'] == 500
