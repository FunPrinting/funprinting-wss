# funprinting-wss

Socket.IO server that pushes print jobs from the FunPrinting web app to partner desktop/mobile apps.

```sh
npm install
cp .env.example .env   # fill in values, then export them (the server does not load .env itself)
npm start              # node index.js
npm test               # node --test
```

## Environment variables

| Name | Required | Purpose |
| --- | --- | --- |
| `WSS_DISPATCH_SECRET` | yes | Shared secret for signing HTTP requests from the web app. |
| `PARTNER_JWT_SECRET` | yes | Verifies the 15-minute access tokens from device sign-in (same value as the web app). Tokens without `typ: partner_access` are refused with `upgrade_required`. |
| `WEB_API_URL` | no | Web app base URL. Errors and warnings are sent, signed, to `${WEB_API_URL}/api/errors` and show up in `/admin/errors`. Unset: log only. |
| `ALLOWED_ORIGINS` | no | Comma-separated browser origins allowed by CORS and Socket.IO. Requests without an `Origin` header are always allowed. |
| `PORT` | no | Listen port (default `3001`). |

The server exits with code 1 on startup if a required variable is missing.

## Socket connections

Clients connect with `auth: { token }`: a device sign-in access token (HS256, `typ: partner_access`, a `did` claim, `role` of `partner` or `admin`, and a 24-character hex `partnerId`). The socket joins room `partner_<partnerId>`. Other tokens get `connect_error: Authentication error: upgrade_required`.

Events:
- Server → client `jobs:available`: `{ reason, at }` (see Job notifications).
- Client → server `remote_control`: `{ action: 'pause' | 'resume' }`. Forwarded to other sockets in the room as `remote_control_action`. Any other action is ignored.

## Device sign-out

`POST /api/disconnect-device` `{ partnerId, deviceId }` (signed) emits `signed_out` to that device's sockets and closes them. Sockets with an access token are also closed when the token expires (15 min); the app reconnects with a refreshed token.

## Job notifications

`POST /api/notify-jobs` `{ partnerId, reason: new|updated|cancelled }` (signed) emits `jobs:available` `{ reason, at }` to `partner_<partnerId>`. It carries no job data: devices then fetch `GET /api/partner/v1/jobs` from the web app.

## Signed HTTP requests

Every `POST /api/*` request from the web app must carry two headers:

- `x-fp-timestamp`: Unix time in milliseconds, as a decimal string.
- `x-fp-signature`: lowercase hex HMAC-SHA256 with key `WSS_DISPATCH_SECRET` over `${timestamp}.${rawBody}`, where `rawBody` is the exact UTF-8 request body.

The server returns 401 if a header is missing, the timestamp is more than 5 minutes off in either direction, or the signature doesn't match. It returns 400 for invalid bodies (`partnerId` must match `/^[0-9a-fA-F]{24}$/`). On success it returns `200 { "success": true, "delivered": <sockets in the partner room> }`. `delivered: 0` means the partner is offline.

```js
const crypto = require('crypto');

async function callWss(path, payload) {
  const body = JSON.stringify(payload); // sign exactly the bytes you send
  const timestamp = Date.now().toString();
  const signature = crypto
    .createHmac('sha256', process.env.WSS_DISPATCH_SECRET)
    .update(`${timestamp}.${body}`)
    .digest('hex');

  const res = await fetch(`${process.env.WSS_URL}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-fp-timestamp': timestamp,
      'x-fp-signature': signature,
    },
    body,
  });
  return res.json(); // { success: true, delivered: n }
}

// callWss('/api/notify-jobs', { partnerId, reason: 'new' });
```
