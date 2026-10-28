# Cookie token delivery — working specification v0.1

**Repository:** `github.com/univeros/polaris-core`, `docs/cookie-mode/`.
**Status:** Draft 1 — 2026-10-28, for the owner's review (§8).
**Baseline:** `main` at 0.11.0.
**Outcome:** `auth.flows.token_delivery: cookie`, documented since 1.0 (`docs/auth/flows.md`, `security.md` §3) and validated by `AuthConfig`, does what the documents say: every route that opens or rotates a Polaris session puts the refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie instead of the JSON body, and the refresh it authenticates is guarded against CSRF. Body mode, the default, does not change by a byte.

This document is written to be executed by an engineer or a coding agent. The work package (§7) has acceptance criteria that can be checked mechanically. Decisions the spec leaves open go into `docs/cookie-mode/decisions.md`, append only.

---

## 0. Ground rules

1. **Body mode is frozen.** With `token_delivery: body` (the default) the pipeline is the one 0.11 runs: the cookie middleware (§2.3) is not even registered. The 184 core fixtures and every package's fixtures replay unchanged through the four hosts.
2. **Only the refresh token moves.** The access token stays a short-lived bearer value the client keeps in memory and sends as `Authorization: Bearer`. The refresh is therefore the only request a cookie authenticates, and the only one the CSRF guard has to cover.
3. **No endpoint class changes.** The token moves in one PSR-15 middleware in `polaris/psr15`, which every host already runs (`Pipeline::handle()` in Slim, the Laravel, Symfony and Yii controllers, and `univeros/polaris`'s `PolarisMiddleware`). Token minting, rotation and reuse detection (`TokenService`) are not touched (AGENT.md rule 7).
4. **Same bar as before.** `composer qa` green, endpoints declared in YAML (rule 6), no `Altair\`, `Cycle\` or `Univeros\` import (rule 3), decisions appended to `decisions.md`.

---

## 1. What exists in 0.11

- `AuthConfig` validates `flows.token_delivery` (`body | cookie`) and stores it in `$tokenDelivery`. Nothing reads that property.
- Fourteen routes answer a token pair with `data.refresh_token` in the body (§2.2); the endpoint or service builds the array directly.
- `POST /auth/token/refresh` reads `refresh_token` through `Input`, which is the body, the cookies and the query merged (`Input::fromServerRequest()`).
- The documents promise "the framework `CsrfMiddleware`" for cookie mode. That is the Univeros class `Altair\Http\Middleware\CsrfMiddleware`: a `_csrf` form field checked against a PHP session, injected into server-rendered HTML forms. It cannot be imported here (rule 3) and does not fit a JSON client.
- `security.md` §9 says the module refuses to set auth cookies over plaintext; `security.md` §11 still has "CSRF guarded in cookie mode" unticked.
- `polaris/multi-session`'s `DeviceMiddleware` recognises a new session by `data.refresh_token` in the response body.
- `TokenService::refresh()` claims a rotation with a compare-and-swap; the loser of two concurrent presentations of one secret takes the replay path and revokes the family. With one cookie shared by every tab, two tabs refreshing at once would sign the user out (§2.8).

---

## 2. Design

### 2.1 What a host gets

A browser application on the same origin as Polaris (or on a trusted origin of the same site, §3) signs in, receives the access token in the body and the refresh token as a cookie it cannot read, refreshes by posting an empty body with one header, and signs out. An injected script can still use the session while the page is open, but it can no longer take a long-lived credential away.

### 2.2 Which routes: the `session` key

A new optional key in the endpoint spec, `endpoint.session`, declares what a route does to the caller's session. The YAML stays the router (rule 6), plugins declare their own routes, and the OAuth provider's `POST /oauth/token`, whose refresh token belongs to an OAuth client and must stay in the body (RFC 6749), is untouched simply by not carrying the key.

| `session` | Routes |
|---|---|
| `issue` | core `POST /auth/login`, `POST /auth/mfa/verify`; `polaris/username` sign-in; `polaris/anonymous` sign-in; `polaris/multi-session` switch; `polaris/passkey` authenticate-verify; `polaris/passwordless` magic-link-exchange, email-otp-verify, phone-verify, one-time-token-verify; `polaris/social` exchange, one-tap; `polaris/sso` exchange |
| `refresh` | core `POST /auth/token/refresh` |
| `end` | core `POST /auth/logout`, `POST /auth/logout-all`; `polaris/sso` `POST /sso/logout` |

`schema.json` gains `"session": { "enum": ["issue", "refresh", "end"] }`; `EndpointSpec` gains `public ?string $session = null`; `Loader` reads and validates it. `polaris manifest` and the OpenAPI document carry it. Adding the key changes no response in body mode.

### 2.3 The middleware

`Polaris\Psr15\Middleware\RefreshCookieMiddleware`, added by `Pipeline::middleware()` only when `token_delivery` is `cookie`, right after `AuthRateLimitMiddleware`:

- after it, so a request the guard refuses still spends the per-IP refresh budget;
- before `MfaTokenMiddleware`, `TokenAuthenticationMiddleware` and every plugin's middleware, so they see requests and responses exactly as body mode produces them. `DeviceMiddleware` keeps reading `data.refresh_token` from the body; the cookie middleware removes it on the way out.

It does nothing on a route without `session`. On a marked route:

| `session` | Before the handler | After the handler |
|---|---|---|
| `issue` | refuse plaintext (§2.6) | on 200 or 201 with a string `data.refresh_token`: remove the key, re-encode the body, add the cookie (§2.4). Anything else (an `mfa_required` ticket, an error) passes unchanged. |
| `refresh` | refuse plaintext; if the body has no `refresh_token` and the request carries the cookie, run the CSRF guard (§2.5) and, when it passes, put the cookie's value into the parsed body as `refresh_token` | on 200: as `issue`. On 401: clear the cookie. |
| `end` | — | on 2xx: clear the cookie. |

The body is re-encoded the way `Polaris\Psr15\JsonResponse` encodes it, and `Content-Length` is dropped or recomputed. The removed key is removed, not set to null.

### 2.4 The cookie

```
Set-Cookie: __Secure-polaris_refresh=<secret>; Path=<prefix>auth/token/refresh; Max-Age=<refresh_token.ttl>; HttpOnly; Secure; SameSite=Strict
```

- **Name.** `__Secure-polaris_refresh`. The `__Secure-` prefix makes the browser reject it unless it is `Secure` and set from HTTPS. `__Host-` is not used because it requires `Path=/`.
- **Path.** The refresh route's full path as the router mounts it (the pipeline's path prefix plus `auth/token/refresh`). The browser sends the cookie to the refresh and nowhere else, so no other route sees it.
- **Max-Age.** `refresh_token.ttl`. The server keeps the real expiry (sliding, `max_lifetime`); a cookie that outlives its token gets a 401 and is cleared.
- **No `Domain`.** Host-only.
- **Clearing** is the same name, path and attributes with an empty value and `Max-Age=0`.

### 2.5 The CSRF guard

The guard runs only when the refresh is authenticated by the cookie (§2.3). All three must hold, or the answer is `403 {"error": "csrf_failed", "message": "..."}`, the handler is not called and the cookie is not consumed:

1. The request carries `X-Polaris-CSRF: 1`. A cross-origin page can only send a custom header after a CORS preflight, and Polaris sends no CORS headers. A host that adds its own CORS layer must not allow this header from an origin outside `trusted_origins`.
2. If `Origin` is present, it equals the request's own origin (scheme, host, port of the request URI) or one of `flows.cookie.trusted_origins`.
3. If `Origin` is absent and `Sec-Fetch-Site` is present, it is `same-origin`.

`SameSite=Strict` already keeps the cookie off cross-site requests; the guard covers what it does not: a same-site sibling origin, and browsers that do not enforce it.

### 2.6 Plaintext

On an `issue` or `refresh` route in cookie mode, a request whose URI scheme is not `https` gets `403 {"error": "insecure_transport", "message": "..."}` before the handler runs, so no session is created that the client could not receive. The scheme is the host's: behind a TLS-terminating proxy, the host's trusted-proxy handling must give the request an `https` URI (Laravel, Symfony and Yii do this from their own configuration; a Slim host does it in its own middleware). This is the refusal `security.md` §9 already describes.

### 2.7 Ending sessions

`end` routes clear the cookie on success. A session that ends another way (password reset's logout-all, an admin revoke, `DELETE /auth/sessions/{id}` on the caller's own session, `polaris/multi-session` revoke) leaves a cookie whose token is dead; the next refresh answers 401 and clears it.

### 2.8 Tabs refreshing at once

No change to `TokenService`: the compare-and-swap and reuse detection stay exactly as they are (rule 7). The client serialises refreshes instead (§2.9): one refresh at a time per browser profile, through the Web Locks API, so a second tab waits for the first and then refreshes with the cookie the first one received.

### 2.9 The TypeScript client

`@polaris-auth/client` keeps its rule (no refresh loop, no storage) and gains:

- `createClient({ tokenDelivery: "cookie", ... })`: the client sends `X-Polaris-CSRF: 1` on `POST /auth/token/refresh`, and leaves `credentials` at the `fetch` default (`same-origin`); a host on a trusted origin passes `credentials: "include"` itself.
- `refreshSession(client)`: posts `{}` to `/auth/token/refresh` inside `navigator.locks.request("polaris:refresh", ...)` when the API exists (one in-flight promise per tab otherwise), and returns the response as `client.POST` does.
- The generated types mark `data.refresh_token` optional on routes whose spec has `session: issue | refresh`, and `refresh_token` optional in the refresh request body.

### 2.10 What does not change

Every response in body mode; every route without `session`; `TokenService`; `polaris/oauth-provider`'s tokens; the access token's transport; `Input`'s merge of cookies into request data (§8, question 7); `univeros/polaris`, which runs the same `Pipeline` and needs only its `^0.11` constraints raised.

---

## 3. Configuration

```php
'flows' => [
    'token_delivery' => 'cookie',          // body (default) | cookie, as today
    'cookie' => [
        'trusted_origins' => [],           // extra origins allowed to refresh, e.g. ['https://app.example.com']
    ],
],
```

`AuthConfig` gains `public array $cookieTrustedOrigins = []`, each entry validated as `scheme://host[:port]` with `https` (fail fast at boot, as the other keys).

---

## 4. Documents to update

- `docs/auth/flows.md` delivery note, `security.md` §3 (token transport) and §9 (transport): the guard of §2.5 replaces "the framework `CsrfMiddleware`"; §11 ticks "CSRF guarded in cookie mode".
- `docs/auth/configuration.md`: `flows.cookie.trusted_origins`.
- `docs/auth/api-reference.md` and `packages/core/api/README.md`: the `session` key and what cookie mode does to the marked routes.
- `packages/psr15/README.md`, `packages/client-ts/README.md`: the middleware, `tokenDelivery` and `refreshSession()`.
- `CHANGELOG.md` for the release.

---

## 5. Tests

Functional tests under `packages/core/tests/Functional` (so they replay through the four harnesses), with cookie mode on and an `https` URI unless stated:

1. Every `issue` route of §2.2 (the plugin ones in each plugin's suite): no `refresh_token` in `data`, every other field as in body mode, one `Set-Cookie` with exactly the attributes of §2.4.
2. Login with a confirmed MFA factor: the `mfa_required` ticket is unchanged and sets no cookie; `/auth/mfa/verify` then sets it.
3. Refresh with the cookie and `X-Polaris-CSRF: 1`: 200, a new cookie, the old secret no longer valid.
4. Refresh with the cookie and no header, with a foreign `Origin`, with `Sec-Fetch-Site: cross-site`: 403 `csrf_failed`; a correct refresh afterwards still succeeds (the token was not consumed).
5. Replay of a rotated cookie: 401, the family revoked, the cookie cleared.
6. Logout, logout-all, SSO logout: the cookie cleared.
7. Any `issue` or `refresh` route over `http`: 403 `insecure_transport`, and no row in `auth_refresh_tokens`.
8. `POST /oauth/token` with `grant_type=refresh_token`: unchanged, body only.
9. `polaris/multi-session`: a cookie-mode sign-in is still recorded against the device.
10. Body mode: the whole existing suite and every fixture, unchanged.

Client: unit tests for the header, the optional types and `refreshSession()` (lock taken, one request per call); the Playwright e2e signs in, refreshes and signs out against the Slim demo in cookie mode, and checks that no JavaScript-readable storage or `document.cookie` holds the refresh token.

---

## 6. Release

One minor release after 0.11 (the next free number when this merges). `univeros/polaris` raises its `polaris/*` constraints in its own repository; nothing else there changes.

---

## 7. Work package

**Branch** `cookie-mode/wp1`, one pull request, after this spec is approved.

**Acceptance criteria**

- [ ] `session` key in `schema.json`, `EndpointSpec`, `Loader`, the manifest and OpenAPI output; the routes of §2.2 marked.
- [ ] `RefreshCookieMiddleware` in `polaris/psr15`, registered only in cookie mode, at the position of §2.3.
- [ ] `flows.cookie.trusted_origins` in `AuthConfig`, validated at boot.
- [ ] Every test of §5 green through Slim, Laravel, Symfony and Yii.
- [ ] Body mode: 184 core fixtures and every package's fixtures byte-identical.
- [ ] `@polaris-auth/client`: `tokenDelivery`, `refreshSession()`, the optional types; unit tests and the cookie-mode e2e green.
- [ ] The documents of §4 updated.
- [ ] `composer qa` green; decisions logged.

---

## 8. Questions for the owner

Defaults are what this spec does if the answer is "fine".

1. **The `session` key** in the endpoint YAML, against a list of route names in the middleware. *Default:* the key (plugins declare their own routes; rule 6).
2. **The CSRF guard**: a custom header plus an `Origin` check (§2.5), against a double-submit token. *Default:* header plus `Origin`; it needs no state and no readable cookie.
3. **Body fallback on refresh in cookie mode**: a refresh that sends `refresh_token` in the body is still accepted (no guard: there is no ambient credential). *Default:* accepted, so nothing a body-mode client does breaks. The alternative is to refuse it in cookie mode.
4. **One mode per host.** A cookie-mode host gives no refresh token in the body to anyone, so a native app on the same host cannot sign in usefully. *Default:* accept that for now; a per-request opt-in (a request header choosing the delivery) is a later change.
5. **Plaintext refusal**: 403 `insecure_transport`, with no exception for `localhost`. *Default:* as written; local development runs behind HTTPS.
6. **Types**: `refresh_token` becomes optional in the generated types of the marked routes, which is a type-level change for body-mode TypeScript users. *Default:* do it in this minor (0.x).
7. **`Input` merges cookies into request data**, after the body and before the query, on every route. In body mode Polaris sets no cookie with a field's name, so nothing is exploitable today, and this spec does not depend on it (the cookie's name is not a field name). It is still a surprise for hosts: should it go in a separate change with its own entry in `docs/extraction/behaviour-changes.md`? *Default:* out of scope here.
8. **Behaviour register.** Cookie mode is opt-in and body mode is unchanged, so no entry in `docs/extraction/behaviour-changes.md`. *Default:* none.

---

## 9. Out of scope

Cross-site deployments (SameSite=None and CORS with credentials), cookie mode for the OAuth provider's clients, a per-request delivery choice, a server-side grace window for concurrent rotation, and any change to `Input` (§8, question 7).
