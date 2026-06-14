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

It should be possible to create an account with fewer privileges than full administrator access, but that has not been mapped out here. If you want least-privilege access, you will need to test which exact permissions SFOS requires for reading firewall rules and toggling their enabled/disabled state.

## Quick Start

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
