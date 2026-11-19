# device-authorization example

The device authorization grant (RFC 8628) from `keycardai-oauth`. A process
with no browser asks the zone for a user code, prints it, and polls until a
person approves the request on another device. With more than one resource,
it then refreshes the token for the first resource.

## Run

```sh
bundle install
KEYCARD_ZONE_URL=https://<your-zone>.keycard.cloud KEYCARD_CLIENT_ID=<client-id> bundle exec bin/device-login
```

| Env var | Meaning |
| --- | --- |
| `KEYCARD_ZONE_URL` | The zone issuer URL (required) |
| `KEYCARD_CLIENT_ID` | An OAuth client with the device code grant enabled (required) |
| `KEYCARD_CLIENT_SECRET` | The client's secret. Without it, the example runs as a public client. |
| `KEYCARD_SCOPES` | Space-separated scopes. Default `openid`, which needs policy to allow the zone's userinfo resource. |
| `KEYCARD_RESOURCES` | Space-separated resource URLs. Each must be a Resource in the zone. |

Ctrl-C while the example waits for approval stops the wait. A poll already in
flight finishes first.

## Verify

`bin/selftest` runs `bin/device-login` against a stub zone, with no network.
The stub answers the first poll with `authorization_pending` and the second
with a 503, so the example resumes once before it gets a token. It checks the
HTTP Basic header, the resources, the refresh, and a public-client run.
