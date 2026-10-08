# Repository automation

Adapted from `timlaing/modbus_local_gateway` and `timlaing/music-assistant-alexa-api`, with Family VPN's native app, dashboard and Home Assistant packaging in mind.

## Metadata and labels

`.github/repository.json` tracks the description, documentation homepage, topics, enabled issues/discussions, merge choices and automatic merged-branch deletion. `.github/labels.json` preserves relevant Modbus label names/colors/descriptions and adds native-platform, VPN, APNs, provisioning, container and release-management labels. Devcontainer and integration-only HA-dev labels are omitted.

Reapply metadata and labels with authenticated GitHub CLI access:

```sh
python3 Tools/configure_github.py            # preview
python3 Tools/configure_github.py --apply    # apply and verify readback
```

The script leaves custom labels intact. It does not configure branch protection or bypass repository rules.

## Issues and pull requests

- Bug, feature, documentation and support forms set an initial type and `needs-triage`. Opening or reopening any issue also adds `needs-triage`; remove it after maintainer review.
- PR metadata labeling uses changed paths and conventional title/branch patterns. `pull_request_target` never checks out or executes PR code. Maintainers should correct suggested labels as necessary.
- Stale processing marks issues after 60 inactive days and closes them 14 days later as `not planned`. `pinned`, `security` and `roadmap` are exempt. PRs are never closed by stale automation.
- Release Drafter updates an unpublished draft on pushes to `main`. `enhancement` suggests minor, `major` suggests major, and other changes default to patch; `skip-changelog` excludes a PR. Review the suggested version against the app manifest before release. Drafting does not sign/push tags or publish images.
- Funding uses the same GitHub Sponsors account as the reference repositories.

## Validation and delivery

- `CI`: pytest on Python 3.12–3.14, dependency checks, standalone AMD64 and Home Assistant AMD64/ARM64 builds, container smoke tests and synthetic Supervisor ingress checks. The hardened add-on test uses a private, root-owned Docker volume to match Supervisor data ownership even on Linux runners.
- `Repository and Home Assistant lint`: actionlint, consistent immutable action references and pinned Home Assistant app schema/semantic validation. The Modbus action-reference checker is adapted to accept full SHA pins; Dependabot maintains them.
- `CodeQL`: Python and JavaScript security analysis on pushes, pull requests and a weekly schedule. Native Swift builds/tests remain in Xcode Cloud.
- Dependabot: weekly Actions, Python and Docker updates. Root and add-on runtime locks must remain identical; CI rejects inconsistent updates. `requirements.txt` wrappers expose the runtime locks to dependency tooling. Review grouped updates and run the complete matrix before merging.
- `Publish container`: a signed version tag triggers reusable CI and lint, then architecture-specific smoke-tested GHCR image publication. Package write access exists only in the publish job. Metadata jobs receive only their required write permissions.

The Alexa app uses signed Home Assistant base images; Family VPN currently uses a Python runtime base. Its Home Assistant base-image signature check is therefore not copied here. Family VPN's published images are not currently Cosign-signed. HACS/hassfest and Modbus integration compatibility jobs are not applicable to this Supervisor app.

See [Home Assistant installation](../docs/HOME_ASSISTANT.md), [release process](../docs/DEPLOYMENT.md) and [Xcode Cloud](../MyVPN/Docs/XCODE_CLOUD.md). Home Assistant currently builds this app from the self-contained repository folder; adding the repository does not deploy native apps or configure the VPN endpoint automatically.
