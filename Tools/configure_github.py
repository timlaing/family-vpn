#!/usr/bin/env python3
"""Apply tracked repository metadata and labels without deleting custom labels."""
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def api(path, method='GET', value=None):
    command = ['gh', 'api', path, '--method', method]
    if value is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(value) if value is not None else None,
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='timlaing/family-vpn')
    parser.add_argument('--apply', action='store_true', help='Apply settings and verify readback')
    args = parser.parse_args()
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
        if previous and previous['color'].lower() == label['color'].lower() and (previous['description'] or '') == label['description']:
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
        if observed_label['color'].lower() != label['color'].lower() or (observed_label['description'] or '') != label['description']:
            raise RuntimeError('Label readback mismatch: '+label['name'])
    print(f'Verified {len(labels)} labels, {len(configuration["topics"])} topics and repository settings for {args.repo}')


if __name__ == '__main__':
    main()
