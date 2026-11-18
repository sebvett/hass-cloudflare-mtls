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

## Installation

**Marketplace / HACS (custom repository):** add
`https://github.com/sebvett/hass-cloudflare-mtls` as a custom repository of type
*Integration*, install **Cloudflare mTLS**, and restart Home Assistant.

**Manual:** copy `custom_components/cloudflare_mtls` into your Home Assistant
`config/custom_components/` folder and restart.

## Setup

Add the integration under Settings → Devices & services → Add integration →
**Cloudflare mTLS** and paste a Cloudflare API token. The integration checks what
the token can do, picks one of two setups, and tells you which one it chose. If the
token can see more than one zone, it asks which zone to use first.

### Automatic: paste a broad token

Use a token with broad access, for example one with all permissions on the account.
At a minimum it needs **SSL and Certificates: Edit**, **Firewall Services: Edit**
and **Zone: Read**; the setup dialog links to a pre-filled token form. Add **DNS:
Edit** and **Cloudflare Tunnel: Edit** for the tunnel route, and **API Tokens:
Edit** so the token can restrict itself.

You choose the hostname (`hass.<zone>` is suggested) and, if the token can see your
remotely managed tunnels, which tunnel should route it. The integration then:

1. requires client certificates on the hostname (mTLS with the Cloudflare-managed CA)
2. adds a WAF custom rule that blocks requests without a valid, unrevoked
   certificate, and optionally Home Assistant's `/api/mcp` on that hostname
3. adds the hostname to the tunnel's public hostnames and creates its DNS record
   (an existing DNS record is never changed)
4. **restricts its own token** to **SSL and Certificates: Edit** on that zone. The
   token value stays the same, so nothing else needs updating.

If the token isn't allowed to edit itself, **Repairs** asks you to swap it for a
restricted one afterwards. The repair links to a pre-filled token form and checks
that the new token really is restricted.

### Manual: set up Cloudflare yourself

Use a token with only **SSL and Certificates: Edit** on the zone, and set up
Cloudflare by hand:

1. Route the hostname to Home Assistant (for example as a tunnel public hostname).
2. SSL/TLS → Client Certificates → Hosts: add the hostname.
3. Security → WAF → Custom rules: add a rule with action *Block*:

   ```
   (http.host eq "hass.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
   ```

   `cert_verified` stays true for revoked certificates, so keep the `cert_revoked`
   check. Without the rule, mTLS alone doesn't block anything.

When you enter the hostname, the integration checks the setup and reports back:

- whether client certificates are required on the hostname (it turns this on if they
  aren't, which the restricted token is allowed to do)
- whether a request without a certificate is actually blocked, by sending one

### Afterwards

- **Reconfigure** replaces the token or changes the hostname.
- Repairs flags it if Cloudflare stops requiring client certificates on the
  hostname, and can turn mTLS back on.
- Devices that were already registered when you set up the integration are left
  alone. Use **Issue certificate** to give one a certificate, or **Adopt
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
