import { afterEach, describe, expect, it, vi } from "vitest";
import { createClient, CSRF_HEADER, REFRESH_LOCK, refreshSession, type paths } from "../src/index.js";

/** A fetch answering every request with an access token, recording what it saw; `gate` holds the answers back. */
function recording(gate: Promise<void> = Promise.resolve()) {
    const requests: Request[] = [];
    const fetch = async (input: Request): Promise<Response> => {
        requests.push(input);
        await gate;
        return new Response(JSON.stringify({ data: { access_token: `at-${requests.length}`, token_type: "Bearer", expires_in: 900 } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    return { requests, fetch };
}

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("cookie token delivery", () => {
    it("sends the CSRF header on every request in cookie delivery, and not in body delivery", async () => {
        const cookie = recording();
        const client = createClient({ baseUrl: "https://polaris.example", tokenDelivery: "cookie", fetch: cookie.fetch });
        await client.POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });
        await client.withToken("at").GET("/auth/me");
        expect(cookie.requests.map((request) => request.headers.get(CSRF_HEADER))).toEqual(["1", "1"]);
        expect(cookie.requests[0]?.credentials).toBe("same-origin");

        const body = recording();
        await createClient({ baseUrl: "https://polaris.example", fetch: body.fetch }).POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });
        expect(body.requests[0]?.headers.has(CSRF_HEADER)).toBe(false);
    });

    it("refreshes with an empty body under the Web Lock, one request per call", async () => {
        const held: string[] = [];
        vi.stubGlobal("navigator", {
            locks: {
                request: async (name: string, callback: () => Promise<unknown>) => {
                    held.push(name);
                    return callback();
                },
            },
        });
        const { requests, fetch } = recording();
        const client = createClient({ baseUrl: "https://polaris.example/api", tokenDelivery: "cookie", fetch });

        const first = await refreshSession(client);
        const second = await refreshSession(client);

        expect(held).toEqual([REFRESH_LOCK, REFRESH_LOCK]);
        expect(requests.map((request) => `${request.method} ${new URL(request.url).pathname}`)).toEqual(["POST /api/auth/token/refresh", "POST /api/auth/token/refresh"]);
        expect(await requests[0]?.json()).toEqual({});
        expect(requests[0]?.headers.get(CSRF_HEADER)).toBe("1");
        expect([first.data?.data.access_token, second.data?.data.access_token]).toEqual(["at-1", "at-2"]);
        expect(first.data?.data.refresh_token).toBeUndefined();
    });

    it("shares one request between concurrent calls without the Web Locks API", async () => {
        vi.stubGlobal("navigator", {});
        let release: () => void = () => undefined;
        const { requests, fetch } = recording(new Promise((resolve) => {
            release = resolve;
        }));
        const client = createClient({ baseUrl: "https://polaris.example", tokenDelivery: "cookie", fetch });

        const calls = [refreshSession(client), refreshSession(client)];
        release();
        const [a, b] = await Promise.all(calls);

        expect(requests).toHaveLength(1);
        expect(a).toBe(b);
        await refreshSession(client);
        expect(requests, "a later call sends its own request").toHaveLength(2);
    });

    it("types the refresh token as optional on the session routes", () => {
        // Compile-time: a success may come without the token, and the refresh body may leave it out.
        type Login = paths["/auth/login"]["post"]["responses"][200]["content"]["application/json"]["data"];
        const session: Extract<Login, { access_token: string }> = { access_token: "at", token_type: "Bearer", expires_in: 900, user: { id: "u", email: "ada@example.com", email_verified: true } };
        const body: NonNullable<paths["/auth/token/refresh"]["post"]["requestBody"]>["content"]["application/json"] = {};
        expect([session.refresh_token, body.refresh_token]).toEqual([undefined, undefined]);
    });
});
