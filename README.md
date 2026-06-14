# Remote Firewall

Small Flask web UI for enabling and disabling selected Sophos Firewall / SFOS firewall rules.

The app is intentionally simple: it shows configured rule names, their current status, source metadata, and a green/red toggle button per rule. It is meant for small internal workflows where a non-firewall-admin user needs a controlled way to toggle one or more predefined rules.

## Disclaimer

This project is unofficial, unsupported, and not affiliated with Sophos.

It uses Sophos Firewall behavior that may change without notice. The default toggle path uses the same internal web-console endpoint that the SFOS GUI uses for enabling and disabling rules, because the public XML API rewrites the firewall rule object and can cause grouped rules to lose their group membership/order.

Use this at your own risk. Test carefully after every SFOS upgrade.

This is probably not appropriate for production unless you fully understand and accept the security tradeoffs:

- the SFOS account needs enough privileges to read and change firewall rules
- the app stores SFOS credentials in an `.env` file
- the app has no built-in authentication
- anyone who can access the app can toggle the configured firewall rules
- the web-console endpoint used by the default method is not a supported public API contract

If you use it, keep it on a trusted internal network, put real authentication in front of it, and restrict access at the network level.

## Features

- Toggle one or more configured SFOS firewall rules.
- Reads current status from SFOS before rendering.
- Sorts rules alphabetically by rule name.
- Shows rule group, source zones, and source networks/devices.
- Docker-based deployment.
- Optional XML API fallback for repair/testing cases.

## Requirements

- Docker and Docker Compose
- Network access from the container host to the SFOS management interface
- A Sophos Firewall account/API user with permission to read and update firewall rules

## Sophos Account Setup

You need to create/use an account on the Sophos Firewall for this app.

The setup tested for this project uses:

- an `api_user` account created on the firewall
- membership in the built-in `administrator` group
- `API access` enabled on the firewall
- API access restricted to specific trusted hosts/IP addresses where possible

This works, but it is broader than ideal. Sophos documents API access as being
controlled by administrator/device-access profiles, and the device-access
permissions used for the web admin console also apply to the API. A profile
permission set to `None` prevents the administrator from seeing that
configuration in the web admin console or getting it through the API.

For a least-privilege profile, start with a dedicated Administrator-type user
and a custom Device access profile, for example `remote-fw-toggle`.

Suggested starting permissions for the default GUI toggle method:

| Profile section | Access | Why |
| --- | --- | --- |
| Rules and policies | Read-write | Required to change firewall rule status. This appears to cover both rules and rule groups in SFOS. |
| Objects | Read-only | Firewall rules commonly reference host, network, and service objects. |
| Network | Read-only | Firewall rules commonly reference zones and network-side configuration. |
| Everything else | None | The app does not need these areas for the default workflow. |

If your configured rules reference extra feature policies, you may need
`Read-only` for those specific areas, for example `IPS`, `Web & content filter`,
`Application filter`, `Traffic shaping`, `WAF`, or `Identity` sections for
user-based rules. Add these only when SFOS rejects a status read/toggle for a
rule that uses that feature.

There does not appear to be a separate per-rule permission in the Device access
profile. `Rules and policies = Read-write` is therefore broader than the app's
own allow-list in `RULE_NAMES`: the app only exposes configured rules, but the
SFOS account itself can still modify firewall policy if its credentials are
misused.

Also restrict the user to the Docker host wherever SFOS allows it:

- enable `API access`
- set `Allowed IP hosts` to the Docker host or a small trusted management host list
- restrict the user's login/device-access source IPs
- expose HTTPS/API device access only on trusted zones, or with a local service
  ACL exception for the trusted host

The exact minimum has not been formally mapped out by Sophos for this app. The
default toggle method uses an internal web-console endpoint rather than a public
XML API operation, so test this profile carefully after SFOS upgrades.

Relevant Sophos documentation:

- https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/API/index.html
- https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/API/HowToArticles/APIAllowAccess/index.html
- https://docs.sophos.com/nsg/sophos-firewall/21.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Profiles/DeviceAccess/index.html

## Quick Start (Docker Image)

This is the recommended setup for normal use. It uses the standalone release
compose file and prebuilt Docker images.

```bash
mkdir remote-fw && cd remote-fw
wget -O docker-compose.yml https://github.com/ssavant2/remote-fw/releases/latest/download/docker-compose.yml
wget -O .env https://github.com/ssavant2/remote-fw/releases/latest/download/example.env

# Edit .env - set SFOS_HOST, SFOS_USERNAME, SFOS_PASSWORD and RULE_NAMES.
chmod 600 .env
docker compose up -d
```

Open:

```text
http://localhost:8090
```

If you bind to a LAN interface, set:

```env
REMOTE_FW_BIND=0.0.0.0
```

If the container cannot resolve `SFOS_HOST` through DNS, download the optional
Compose override:

```bash
wget -O docker-compose.override.yml https://github.com/ssavant2/remote-fw/releases/latest/download/docker-compose.override.yml.example
```

Then set `SFOS_EXTRA_HOST_IP` in `.env`.

## Update

```bash
docker compose pull && docker compose up -d
```

If release notes mention changes to the standalone compose file, re-download
`docker-compose.yml` before updating.

## Quick Start (Local Build)

This setup builds the Docker image locally from the cloned repository.

Copy the example environment file:

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env`:

```env
SFOS_HOST=firewall.example.local
SFOS_EXTRA_HOST_IP=192.0.2.10
SFOS_PORT=4444
SFOS_USERNAME=api-user
SFOS_PASSWORD=change-me
SFOS_VERIFY_TLS=false
SFOS_TIMEOUT=120

RULE_NAMES=Example Firewall Rule,Another Example Rule
APP_TITLE=Remote Firewall
REMOTE_FW_BIND=127.0.0.1
REMOTE_FW_PORT=8090
```

If the container cannot resolve `SFOS_HOST` through DNS, enable the optional Compose override:

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
```

Then set `SFOS_EXTRA_HOST_IP` in `.env`.

Start the app:

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8090
```

If you bind to a LAN interface, set:

```env
REMOTE_FW_BIND=0.0.0.0
```

## Configuration

`RULE_NAMES` is a comma-separated list of SFOS firewall rule names:

```env
RULE_NAMES=Rule A,Rule B,Rule C
```

The rule names must match the names in SFOS.

`SFOS_VERIFY_TLS=false` can be useful in lab/internal environments where the container does not trust the firewall certificate chain. For a cleaner setup, install the issuing CA certificate in the image/container and enable TLS verification.

## Toggle Method

By default, the app uses:

```env
SFOS_TOGGLE_METHOD=gui
```

This logs in to the SFOS web console and calls the internal endpoint used by the GUI for enable/disable. In testing, this preserved rule group membership and rule order.

The older XML API path is still available:

```env
SFOS_TOGGLE_METHOD=xml
```

The XML path updates the rule through the SFOS XML API and then attempts to restore group membership/order when needed. It is slower and is kept mainly as a fallback/repair path.

## Security Notes

Do not commit `.env`.

The `.gitignore` and `.dockerignore` files exclude `.env` and `.env.*` by default, except for `.env.example`.

The published Docker setup includes a basic hardening baseline:

- runs as a non-root user (`1000:1000`)
- drops all Linux capabilities
- enables `no-new-privileges`
- uses a read-only root filesystem
- mounts only `/tmp` as tmpfs with `noexec`, `nosuid`, and `nodev`
- sets process and memory limits
- rotates container logs
- sends basic browser security headers, including CSP, `X-Frame-Options`, and `nosniff`
- blocks cross-origin state-changing requests unless explicitly allowed
- limits request body size
- uses Dependabot for Python, Docker, and GitHub Actions dependency checks

The Docker image uses `uv` during the build to install Python dependencies into a virtual environment. `uv` and `pip` are not needed at runtime.

For real use, consider:

- running behind Authentik, Authelia, Nginx auth, or another trusted auth layer
- binding only to localhost and exposing it through a reverse proxy
- limiting source IPs with host firewall rules
- using a dedicated SFOS account
- rotating the SFOS password if the `.env` file may have been exposed
- keeping VM/container-host backups protected, since they contain the `.env` file

## Development Helper

The probe tool can read/toggle configured rules from the command line:

```bash
python3 tools/sfos_probe.py status
```

It reads the same `.env` settings as the web app.

## License

MIT. See [LICENSE](LICENSE).
