> Version 0.3.0: authenticated POST status and command acknowledgements may be public; registration is restricted to 192.168.150.0/24; remaining REST routes stay VPN-only. See the repository `docs/REMOTE_COMMANDS.md` for complete setup instructions.

# Deployment and releases

For the Home Assistant package and NPM custom location, start with [Home Assistant deployment](HOME_ASSISTANT.md). The source/container sections below describe standalone mode.

## Source deployment

Use Python 3.12–3.14, install `requirements.lock` into a dedicated virtual environment and configure variables from `.env.example`. Generate separate random ADMIN_BEARER, REGISTRATION_BEARER and SESSION_SECRET values. Store them privately outside Git. The service reads its process environment; it does not load `.env` automatically.

Run as a dedicated service account with a persistent, private SQLite directory and read-only APNs provider key. Use exactly one worker:

```sh
.venv/bin/gunicorn --workers 1 --threads 4 --bind 127.0.0.1:8081 \
  --access-logfile /dev/null --error-logfile - wsgi:application
```

A trusted HTTPS reverse proxy must sit in front of this loopback listener. Set LOCAL_HTTP=false. Restrict access to administrators, limit requests/rate at ingress, and avoid logging headers, cookies or bodies. Forward paths without changing the registration/status prefix. Do not use Gunicorn `--preload` or multiple replicas: the scheduler must be created inside a single serving process.

## Configuration

| Variable | Purpose/default |
| --- | --- |
| ADMIN_BEARER | Dashboard/API credential, required 32+ characters |
| REGISTRATION_BEARER | Enrollment credential, required 32+ characters |
| SESSION_SECRET | Cookie-signing credential, required 32+ characters |
| VPNWEB_DATABASE | SQLite file; source default `data/vpnweb.sqlite`, container `/data/vpnweb.sqlite` |
| APNS_KEY_FILE | Read-only P-256 provider key path |
| APNS_KEY_ID / APNS_TEAM_ID | Apple provider identity |
| APNS_TOPIC | `uk.co.laingcorp.myvpn`; match actual application |
| APNS_ENVIRONMENT | `sandbox` or `production`; default sandbox |
| WATCHDOG_INTERVAL_SECONDS | 1800–3600; default 2700 |
| AUTO_PUSH | `true` schedules checks when provider fields are present; default true |
| LOCAL_HTTP | Default false; true only for loopback development |

Start with AUTO_PUSH=false. Check the native build's APNs environment and team/topic before enabling delivery. A provider key/path is not verified until a send is attempted. `/health` cannot establish provider validity.

## Container deployment

```sh
docker build -t vpnweb:local .
bash Tools/smoke_container.sh vpnweb:local
```

The image runs UID/GID 10001 and needs a writable `/data` volume. A fresh named volume inherits the image directory ownership; pre-existing/bind-mounted data must be owned by 10001 and private. The APNs key must be readable by that UID while unavailable to other users. In the private production env file set APNS_KEY_FILE=/run/secrets/apns.p8 and LOCAL_HTTP=false.

Replace the illustrative host paths before running:

```sh
docker run -d --name vpnweb --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --env-file /private/path/vpnweb.env \
  --mount type=volume,source=vpnweb-data,target=/data \
  --mount type=bind,source=/private/path/apns.p8,target=/run/secrets/apns.p8,readonly \
  -p 127.0.0.1:8081:8081 vpnweb:local
```

Use your HTTPS proxy for external access. Docker publishes loopback only. Do not put secrets in the image build context; `.dockerignore` allowlists application runtime files. The standalone image targets Linux amd64 in the GitHub workflow; Home Assistant app images target amd64 and aarch64. Local Docker builds use the host architecture. Use source deployment or build locally for other architectures.

## CI and publication

CI runs on main pushes, pull requests and manual invocation. It installs locked dependencies, runs the service tests on Python 3.12/3.13/3.14, checks compilation and builds/smoke-tests the container. No APNs credentials are available to tests. GitHub Actions are pinned to commits; Dependabot checks actions and the Docker base weekly. Python lock updates require the clean-environment procedure in CONTRIBUTING.md.

To release, update CHANGELOG.md with a version and date, merge passing changes, then create and push a signed `vMAJOR.MINOR.PATCH` or prerelease tag using your own signing key. The tag workflow reruns CI, builds and smoke-tests the image, then publishes:

- `ghcr.io/<owner>/<repository>:vMAJOR.MINOR.PATCH`
- `ghcr.io/<owner>/<repository>:sha-<full-commit-sha>`

It uses GITHUB_TOKEN with packages write permission only in the publishing job. Configure a GitHub remote and push the repository first; none is currently configured locally. Enable Actions and package publication in repository/organization settings. Packages are subject to your GitHub visibility/access settings. Private registry consumers need read access; do not reuse the APNs key for registry authentication.

No mutable `latest` tag is published. Save the pushed image digest from the workflow and deploy that digest for reproducibility. Tag publication is continuous delivery of an image, not automatic installation on a live host. No SSH credentials or server target have been configured, and these workflows have not yet run on GitHub.

## Verification and rollback

Before first production use, check HTTPS, restricted login, enrollment, one manual APNs request, and a subsequent physical-device status report. Re-enrollment rotates the report credential. Acceptance alone cannot prove delivery. Verify scheduling separately before enabling AUTO_PUSH.

Before an upgrade, stop the service and take a private backup of the SQLite database and any SQLite sidecar files, recording the previous image digest/source commit. Restore owner/mode when copying a backup. Protect backups like the live database; they contain device tokens.

Deploy the tested image digest with the same data volume and check `/health`, authenticated dashboard and one device report. To roll back, stop the service and start the previous digest with compatible data. Review future schema migration notes before rollback; 0.3.0 uses additive device/command columns and a new administrator configuration table; restore a compatible backup if rolling back across schema versions. Database replacement requires device re-enrollment. Rotating SESSION_SECRET signs users out; enrollment credential changes require updating clients. Revoke APNs credentials at Apple if exposed.

Home Assistant installs currently build the self-contained `family_vpn/` context locally through Supervisor. The GHCR tag workflow publishes tested architecture-specific add-on images as well as a standalone image. No `image` URL is hardcoded in config.yaml until a repository/registry path is established; CI verifies the tagged version matches the app manifest.

The architecture-specific app image names are `ghcr.io/<owner>/<repository>-family-vpn-amd64:0.3.0` and `...-family-vpn-aarch64:0.3.0` for tag v0.3.0. Native ARM runner availability depends on your GitHub plan/repository settings; local Supervisor builds remain available. The standalone image uses the original repository image name and v-prefixed tag.
