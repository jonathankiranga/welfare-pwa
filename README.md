# Smarternow PWA — welfare.smarternowapps.co.ke
Admin + API for contacts/groups. One-way fetch for Android, archive-only, device-lock (single APK).

## Stack
- Node.js Express on Render
- MySQL TiDB (`gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000`)
- Endpoints: `POST /api/device/register`, `POST /api/device/request-otp`, `POST /api/device/transfer`, `GET /api/contacts.json?since=`, `POST /api/contacts/upsert`, `POST /api/contacts/archive`, `GET /health`
- Admin at `/admin` (Basic Auth + OTP transfer UI)

## Env
```
TIDB_HOST=gateway01.ap-southeast-1.prod.aws.tidbcloud.com
TIDB_PORT=4000
TIDB_USER=xxx
TIDB_PASS=xxx
TIDB_DB=smarternow
TIDB_CA=./certs/tidb-ca.pem
PWA_API_KEY=shared-read-key
DEVICE_BINDING_ENABLED=true
OTP_TTL_SEC=300
ADMIN_USER=admin
ADMIN_PASS=xxx
AT_API_KEY=optional-for-otp-sms
```
Run: `npm install && npm start`
