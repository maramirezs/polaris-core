import { expect, test } from "@playwright/test";

/**
 * Cookie token delivery in Chromium against the Slim demo (POLARIS_TOKEN_DELIVERY=cookie, behind the TLS proxy of
 * playwright.config.ts): sign in, refresh with an empty body, sign out, as `@polaris-auth/client` with
 * `tokenDelivery: "cookie"` sends them (the X-Polaris-CSRF header, same-origin credentials). The refresh token is
 * never readable by the page: not in a body, not in `document.cookie`, not in storage.
 */
const cookieURL = process.env["POLARIS_COOKIE_URL"] ?? (process.env["POLARIS_URL"] ? undefined : "https://localhost:8443");

test.use({ ignoreHTTPSErrors: true });

test("the refresh token lives in an HttpOnly cookie the page never sees", async ({ page, context }) => {
    test.skip(cookieURL === undefined, "POLARIS_URL is set without POLARIS_COOKIE_URL");
    const origin = cookieURL ?? "";
    await page.goto(`${origin}/passkey.html`);

    const signedIn = await page.evaluate(async () => {
        const api = async (path: string, body: unknown, token?: string) => {
            const headers: Record<string, string> = { "Content-Type": "application/json", "X-Polaris-CSRF": "1" };
            if (token !== undefined) headers["Authorization"] = `Bearer ${token}`;
            const response = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
            return { status: response.status, json: await response.json().catch(() => ({})) };
        };
        const email = `cookie+${Date.now()}@example.com`;
        const password = "Sup3r-Secret-Passw0rd";
        await api("/auth/register", { email, password });
        // Both demos write one mailbox: this user's verification mail, not the last one.
        const mail = (await (await fetch(`/mailbox?${Date.now()}`)).text()).split("\n").filter((line) => line.includes(`"${email}"`)).join("\n");
        const token = [...mail.matchAll(/"token":"([^"]+)"/g)].at(-1)?.[1];
        await api("/auth/email/verify", { token });
        const login = await api("/auth/login", { email, password });

        return { email, password, login, cookie: document.cookie };
    });
    expect(signedIn.login.status).toBe(200);
    expect(Object.keys(signedIn.login.json.data)).toEqual(["access_token", "token_type", "expires_in", "user"]);
    expect(signedIn.cookie).not.toContain("polaris_refresh");
    const [cookie] = (await context.cookies(`${origin}/auth/token/refresh`)).filter((candidate) => candidate.name === "__Secure-polaris_refresh");
    expect(cookie).toMatchObject({ path: "/auth/token/refresh", httpOnly: true, secure: true, sameSite: "Strict", domain: "localhost" });

    const flow = await page.evaluate(async () => {
        const post = async (path: string, token?: string) => {
            const headers: Record<string, string> = { "Content-Type": "application/json", "X-Polaris-CSRF": "1" };
            if (token !== undefined) headers["Authorization"] = `Bearer ${token}`;
            const response = await fetch(path, { method: "POST", headers, body: "{}" });
            return { status: response.status, json: await response.json().catch(() => ({})) };
        };
        const withoutHeader = (await fetch("/auth/token/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status;
        const refreshed = await post("/auth/token/refresh");
        const me = (await fetch("/auth/me", { headers: { Authorization: `Bearer ${refreshed.json.data?.access_token}` } })).status;
        const logout = await post("/auth/logout", refreshed.json.data?.access_token);
        const after = await post("/auth/token/refresh");

        return { withoutHeader, refreshed, me, logout, after, cookie: document.cookie, storage: localStorage.length + sessionStorage.length };
    });
    expect(flow.withoutHeader, "the CSRF guard").toBe(403);
    expect(flow.refreshed.status).toBe(200);
    expect(Object.keys(flow.refreshed.json.data)).toEqual(["access_token", "token_type", "expires_in"]);
    expect(flow.me).toBe(200);
    expect(flow.logout.status).toBe(200);
    expect(flow.after.status, "signed out: no cookie, no token").toBe(422);
    expect(flow.cookie).not.toContain("polaris_refresh");
    expect(flow.storage).toBe(0);
    expect((await context.cookies(`${origin}/auth/token/refresh`)).map((candidate) => candidate.name)).not.toContain("__Secure-polaris_refresh");
});
