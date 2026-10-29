import { defineConfig } from "@playwright/test";
import { resolve } from "node:path";

/**
 * The browser side of the Slim demo (examples/slim): Chromium with a virtual authenticator against the
 * demo served by PHP's built-in server on its own port (the smoke test holds 8080 for a while).
 * `composer install && bin/setup` in examples/slim first; run from packages/client-ts (`npm run e2e`).
 * localhost, not 127.0.0.1: the demo binds its passkeys to the domain. The cookie-delivery run gets a second demo
 * behind a TLS proxy (openssl generates its certificate).
 */
const demo = resolve(process.cwd(), "../../examples/slim");
const port = 8090;
const baseURL = process.env["POLARIS_URL"] ?? `http://localhost:${port}`;
// The cookie-delivery demo: the same app with POLARIS_TOKEN_DELIVERY=cookie on its own port, behind the local TLS
// proxy (e2e/tls-proxy.mjs), since cookie delivery refuses plaintext. POLARIS_COOKIE_URL points at a running one.
const cookiePort = 8091;
const cookieTlsPort = 8443;
const cookieURL = process.env["POLARIS_COOKIE_URL"] ?? `https://localhost:${cookieTlsPort}`;
const php = (listen: number) => `php -S 127.0.0.1:${listen} -t "${resolve(demo, "public")}" "${resolve(demo, "public/index.php")}"`;

export default defineConfig({
    testDir: "./e2e",
    timeout: 60_000,
    retries: 0,
    reporter: process.env["CI"] ? "github" : "list",
    use: { baseURL, trace: "retain-on-failure" },
    projects: [{ name: "chromium", use: { browserName: "chromium" } }],
    webServer: process.env["POLARIS_URL"] ? undefined : [
        {
            command: php(port),
            cwd: demo,
            // The demo binds its callbacks and passkeys to this origin (its .env does not override the environment).
            env: { POLARIS_BASE_URL: baseURL },
            // A static file: php -S answers 404 for a routed path whose extension looks static (`.json`).
            url: `http://127.0.0.1:${port}/passkey.html`,
            reuseExistingServer: false,
            timeout: 30_000,
        },
        {
            command: php(cookiePort),
            cwd: demo,
            env: { POLARIS_BASE_URL: cookieURL, POLARIS_TOKEN_DELIVERY: "cookie" },
            url: `http://127.0.0.1:${cookiePort}/passkey.html`,
            reuseExistingServer: false,
            timeout: 30_000,
        },
        {
            command: `node e2e/tls-proxy.mjs ${cookieTlsPort} ${cookiePort}`,
            port: cookieTlsPort,
            reuseExistingServer: false,
            timeout: 30_000,
        },
    ],
});
