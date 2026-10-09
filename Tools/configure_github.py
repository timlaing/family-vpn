#!/usr/bin/env python3
"""Apply tracked repository metadata and labels without deleting custom labels."""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def api(path, method='GET', value=None):
    if not re.fullmatch(r'repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/topics)?', path) or method not in {'GET', 'PATCH', 'PUT'}:
        raise ValueError('Invalid repository API endpoint or method')
    command = ['gh', 'api', '--method', method, '--', path]
    if value is not None:
        command[2:2] = ['--input', '-']
    result = subprocess.run(command, input=json.dumps(value) if value is not None else None,
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def label_matches(previous, expected):
    return bool(previous) and previous['color'].lower() == expected['color'].lower() and (previous['description'] or '') == expected['description']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='timlaing/family-vpn')
    parser.add_argument('--apply', action='store_true', help='Apply settings and verify readback')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', args.repo):
        parser.error('Use a GitHub owner/repository identifier')
    configuration = json.loads((ROOT/'.github/repository.json').read_text())
    labels = json.loads((ROOT/'.github/labels.json').read_text())
    if not args.apply:
        print(json.dumps({'repo':args.repo, **configuration, 'labels':labels}, indent=2))
        return
    endpoint = 'repos/' + args.repo
    api(endpoint, 'PATCH', configuration['settings'])
    api(endpoint+'/topics', 'PUT', {'names':configuration['topics']})
    current = json.loads(subprocess.check_output(['gh','label','list','--repo',args.repo,'--limit','200','--json','name,color,description'],text=True))
    existing = {label['name']:label for label in current}
    for label in labels:
        previous = existing.get(label['name'])
        if label_matches(previous, label):
            continue
        subprocess.run(['gh','label','create',label['name'],'--repo',args.repo,'--color',label['color'],
                        '--description',label['description'],'--force'],check=True)
    observed = api(endpoint)
    for field, expected in configuration['settings'].items():
        if observed[field] != expected: raise RuntimeError('Repository readback mismatch: '+field)
    if set(api(endpoint+'/topics')['names']) != set(configuration['topics']): raise RuntimeError('Topic readback mismatch')
    observed_labels = json.loads(subprocess.check_output(['gh','label','list','--repo',args.repo,'--limit','200','--json','name,color,description'],text=True))
    by_name = {label['name']:label for label in observed_labels}
    for label in labels:
        observed_label = by_name[label['name']]
        if not label_matches(observed_label, label):
            raise RuntimeError('Label readback mismatch: '+label['name'])
    print(f'Verified {len(labels)} labels, {len(configuration["topics"])} topics and repository settings for {args.repo}')


if __name__ == '__main__':
    main()
