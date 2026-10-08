#!/usr/bin/env python3
"""Adapted from modbus_local_gateway: consistent, immutable action references."""
import re
from pathlib import Path


def main():
    references = {}
    errors = []
    for path in sorted(Path('.github/workflows').glob('*.y*ml')):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = re.search(r'uses:\s+([\w./-]+)@([^\s#]+)', line)
            if not match:
                continue
            action, revision = match.groups()
            repository = '/'.join(action.split('/')[:2])
            if not re.fullmatch(r'[0-9a-f]{40}', revision):
                errors.append(f'{path}:{number}: pin {action} to a full commit SHA')
            if repository in references and references[repository] != revision:
                errors.append(f'{path}:{number}: inconsistent references for {repository}')
            references[repository] = revision
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Action references verified for {len(references)} action repositories')


if __name__ == '__main__':
    main()
