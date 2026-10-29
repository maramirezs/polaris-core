# Decisions log (cookie token delivery)

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected.

## Open at start (decide before WP1)

- The owner's questions in `spec.md` §8.

## Log

<!-- YYYY-MM-DD · WPn · decision · reason · rejected alternatives -->

- 2026-10-29 · WP1 · No `conflict` entries in `polaris/core`'s `composer.json` (spec §2.2). Every package requires its siblings with a `^0.<minor>` caret, which in Composer's 0.x rules excludes the next minor: a 0.11 plugin cannot install next to the core release that reads `session`, so the version skew §2.2 guards against cannot happen in a minor release. The coverage test stays (`ManifestTest::testEveryRouteThatAnswersARefreshTokenDeclaresItsSession`): it catches a future route that forgets the key. · Rejected: the `conflict` entries (redundant with the carets, and one more list the release has to keep in step).
- 2026-10-29 · WP1 · Refusal envelope (§8 question 9, default kept): `csrf_failed` and `insecure_transport` answer `{error, message}` on a core route and, on a plugin route, the problem document `Endpoint::problem()` would build (`type` `https://polaris.univeros.io/problems/<code>`, `error` the same code). Worth knowing for the answer: core's own middleware already answers the core envelope on plugin routes (`UnauthorizedResponder`'s 401), so "core envelope everywhere" has precedent. · Rejected for now: the core envelope everywhere; the owner may prefer it.
- 2026-10-29 · WP1 · The optional `refresh_token` types come from `OpenApi::document()`, which reads `session` (`x-polaris-session`, `data.refresh_token` out of `required`, the refresh body's `refresh_token` optional, the two 403s listed); the YAML keeps `rules: [required]`. `polaris/mcp`'s `ToolSchema` asks for `cookieDelivery: false`, because a tool call always answers in the body: its tool schemas, and the recorded `tools/list` fixture, stay as in 0.11. · Rejected: editing the YAML rules (the server validates them), post-processing in the TypeScript generator (the OpenAPI document is what every consumer reads).
- 2026-10-29 · WP1 · No harness change was needed for `https`: `symfony/psr-http-message-bridge` already sets `HTTPS=on` from the PSR-7 URI's scheme (spec §5 assumed it did not). Cookie-mode tests build `https://localhost` URIs, pass the cookie as a cookie param, compare `Set-Cookie` as parsed attributes (Symfony re-serialises it, an emptied cookie becomes `deleted` with `Max-Age=0`), and record no contract fixtures. `FunctionalTestCase::authConfig()` is the per-class hook; the shared helpers are the `CookieDelivery` trait. · Rejected: recording fixtures for cookie mode (the hosts' `Set-Cookie` differs byte for byte, as multi-session's device cookie already showed).
- 2026-10-29 · WP1 · The cookie's `Path` is the path of the manifest route marked `session: refresh` under the pipeline's prefix, not a literal. The rewritten body is decoded to objects, so an empty object stays one, and encoded with `JsonResponse`'s flags, so the bytes differ from body delivery by the removed key alone (unit-tested). · Rejected: a hard-coded `/auth/token/refresh`; decoding to arrays.
- 2026-10-29 · WP1 · The e2e runs a second Slim demo with `POLARIS_TOKEN_DELIVERY=cookie` behind `e2e/tls-proxy.mjs` (Node `https` with a throwaway `openssl` certificate) and the demo's `ForwardedHttps` middleware, which trusts `X-Forwarded-Proto` from loopback only. It drives `fetch` from the page, as the passkey e2e does, rather than bundling the client into the page; the client's header and Web Lock are unit-tested. · Rejected: a localhost exception to the plaintext refusal (§8 question 5).

