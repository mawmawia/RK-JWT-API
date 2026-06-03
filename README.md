# RK JWT API v2

**Part of Rael_Kertia Empire** | API #003

The JWT API that jwt.io can't be. Decode, verify, sign, inspect JWTs + JWKS support. Built for CI/CD, edge, and production debugging.

## Why RK JWT?
jwt.io is client-side only. Use RK JWT in CI/CD, Lambda, Vercel Edge, Cloudflare Workers. No crypto libs in your app.

## Endpoints
`POST /api`

### Actions

**1. Decode + Expiry Check**
```bash
curl -X POST https://rk-jwt-api.vercel.app/api \
  -H "Content-Type: application/json" \
  -d '{"action":"decode","token":"eyJhbG..."}'
