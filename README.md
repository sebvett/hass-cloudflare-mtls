# Cloudflare mTLS for Home Assistant

Put Home Assistant behind Cloudflare with **mutual TLS** and let the companion app
through automatically: every app install gets its own client certificate when it
first registers, and loses it when the install is removed.

Cloudflare Access can't protect the companion app, which can't complete an Access
login. A client certificate works, because the app presents one when the server asks for it. Zone-level mTLS with the
Cloudflare-managed CA is available on **all Cloudflare plans**, including Free.

## How it works

1. A phone installs the Home Assistant app and signs in **on the local network**.
2. The integration sees the new `mobile_app` registration, generates an ECDSA P-256
   key, has Cloudflare sign a certificate for it, and packs both into a
   password-protected `.p12`.
3. The phone gets a notification: **Remote access certificate → Install**. The link
   opens a one-time page on Home Assistant's *local* URL that shows the password and
   offers the download. The push carries only the link, never the password or the file.
4. The user installs the certificate; from then on the app connects through
   Cloudflare from anywhere.
5. When the device is removed from Home Assistant (Settings → Devices & services →
   Mobile App → device → Delete), its certificate is revoked in Cloudflare.

The download page:

- answers only local client addresses (as Home Assistant sees them after
  reverse-proxy handling), and refuses any request carrying Cloudflare headers, so
  it can't be reached through Cloudflare even with a valid certificate
- expires after 24 hours, or 10 minutes after the file is downloaded

Each device has its own certificate, so a lost phone is cut off by deleting that one
device. Nobody else has to re-enrol. Home Assistant's own login still applies on top.

## Requirements

- Home Assistant 2026.11 or later
- A Cloudflare zone serving Home Assistant (for example through a Cloudflare Tunnel)
- Home Assistant configured to trust your reverse proxy (Settings → System →
  Network: *Trust X-Forwarded-For* and *Trusted proxies*)

## Cloudflare setup

1. **Enable mTLS for the hostname**: SSL/TLS → Client Certificates → Hosts → add
   the hostname Home Assistant is served on.
2. **Block requests without a valid certificate**: Security → WAF → Custom rules →
   action *Block*:

   ```
   (http.host eq "ha.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
   ```

   `cert_verified` stays true for revoked certificates, so keep the `cert_revoked`
   check. It's also worth blocking `/api/mcp` here if you use Home Assistant's MCP server.
3. **Create an API token**: My Profile → API Tokens → Create token → Custom token,
   permission **Zone → SSL and Certificates → Edit**, limited to your zone.

## Installation

**Marketplace / HACS (custom repository):** add
`https://github.com/sebvett/hass-cloudflare-mtls` as a custom repository of type
*Integration*, install **Cloudflare mTLS**, and restart Home Assistant.

**Manual:** copy `custom_components/cloudflare_mtls` into your Home Assistant
`config/custom_components/` folder and restart.

Then add it under Settings → Devices & services → Add integration →
**Cloudflare mTLS**, and enter the API token and the zone ID (shown on the zone's
Overview page). The token is checked before it's saved, and can be replaced later
with **Reconfigure**.

Devices that were already registered when you set up the integration are left
alone. Use the **Issue certificate** action to give one a certificate, or **Adopt
certificate** to register one you made in the Cloudflare dashboard.

## Actions

| Action | What it does |
|---|---|
| `cloudflare_mtls.issue` | Issue a new certificate for a device, revoke its old one, and push a new link. Returns the link. |
| `cloudflare_mtls.revoke` | Revoke a device's certificate. |
| `cloudflare_mtls.adopt` | Record an existing Cloudflare certificate as a device's, so it's revoked with the device. |
| `cloudflare_mtls.list` | List app installs, their certificate IDs and any pending links. |

## Installing the certificate

**Android:** open the downloaded `hass.p12`. If the phone won't install it from
there, use Settings → Security & privacy → More security settings → Encryption &
credentials → Install a certificate → **VPN & app user certificate**. The app asks
which certificate to use the next time it connects.

**iOS:** import the `.p12` in the Home Assistant app's server settings (client
certificate). iOS doesn't present the certificate for background requests, so
location and sensor updates won't reach Home Assistant through Cloudflare. The app
works normally in the foreground.

## Notes

- Certificates are valid for 10 years. Cloudflare allows 100 active client
  certificates per zone by default.
- A newly issued certificate can take a few minutes before Cloudflare accepts it.
- The certificate is generated on your Home Assistant host. Until it's downloaded or
  expires, the `.p12` and its password are kept in `.storage/cloudflare_mtls`.

## License

MIT
