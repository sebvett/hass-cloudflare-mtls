# Cloudflare mTLS for Home Assistant

Put Home Assistant behind Cloudflare with **mutual TLS** and let the companion app
through automatically: every app install gets its own client certificate when it
first registers, and loses it when the install is removed.

## How it works

1. A phone installs the Home Assistant app and signs in **on the local network**.
2. The integration sees the new `mobile_app` registration, generates an ECDSA P-256
   key, has Cloudflare sign a certificate for it, and packs both into a
   password-protected `.p12`.
3. The phone gets a notification: **Remote access certificate → Install**. The link
   opens a one-time page on Home Assistant's *local* URL that shows the password and
   offers the download.
4. When the device is removed from Home Assistant (Settings → Devices & services →
   Mobile App → device → Delete), its certificate is revoked in Cloudflare.

## Requirements

- Home Assistant 2026.11 or later
- A Cloudflare zone serving Home Assistant
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
**Cloudflare mTLS** and paste a Cloudflare API token.

### Automatic: paste a broad token

Use a token with broad access, for example one with all permissions on the account.
At a minimum it needs **SSL and Certificates: Edit**, **Firewall Services: Edit**
and **Zone: Read**. Add **DNS: Edit** and **Cloudflare Tunnel: Edit** for the
tunnel route, and **API Tokens: Edit** so the token can restrict itself.

The integration then:

1. requires client certificates on the hostname
2. adds a WAF custom rule that blocks requests without a valid, unrevoked
   certificate, and optionally Home Assistant's `/api/mcp` on that hostname
3. adds the hostname to the tunnel's public hostnames and creates its DNS record
4. **restricts its own token** to **SSL and Certificates: Edit** on that zone

If the token isn't allowed to edit itself, **Repairs** asks you to swap it for a
restricted one afterwards.

### Manual: set up Cloudflare yourself

Use a token with only **SSL and Certificates: Edit** on the zone, and set up
Cloudflare by hand:

1. Route the hostname to Home Assistant (for example as a tunnel public hostname).
2. SSL/TLS → Client Certificates → Hosts: add the hostname.
3. Security → Security rules → Create rule → Custom rules: action *Block*, expression:

   ```
   (http.host eq "hass.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
   ```

   `cert_verified` stays true for revoked certificates, so keep the `cert_revoked`
   check. Without the rule, mTLS alone doesn't block anything.

The integration checks this setup when you enter the hostname.

### Afterwards

Devices that were already registered when you set up the integration are left
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
credentials → Install a certificate → **VPN & app user certificate**.

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
