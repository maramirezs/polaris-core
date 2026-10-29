import type { Client, Middleware } from "openapi-fetch";
import type { paths } from "./schema.js";

/** The header the CSRF guard of cookie delivery requires on every sign-in and refresh (docs/cookie-mode/spec.md §2.5). */
export const CSRF_HEADER = "X-Polaris-CSRF";

/** The Web Lock every tab of the origin queues on, so one refresh runs at a time (spec §2.8). */
export const REFRESH_LOCK = "polaris:refresh";

/** Sends the CSRF header on every request: the guard needs it on the sign-in and refresh routes, and it is harmless elsewhere. */
export function cookieDelivery(): Middleware {
    return {
        onRequest({ request }) {
            request.headers.set(CSRF_HEADER, "1");
            return request;
        },
    };
}

type RefreshResult = ReturnType<Client<paths>["POST"]>;

let inFlight: RefreshResult | null = null;

/**
 * Rotates the session the refresh cookie holds: an empty `POST /auth/token/refresh`, answered as `client.POST`
 * answers it (a fresh access token in `data`; the next refresh token in the cookie). With rotation, two tabs
 * presenting one cookie at once would trip reuse detection and end the session, so the call runs under the Web
 * Lock {@link REFRESH_LOCK} and a second tab waits for the first, then refreshes with the cookie the first one
 * received. Without the Web Locks API, concurrent calls in this tab share one request.
 */
export function refreshSession(client: Client<paths>): RefreshResult {
    const refresh = () => client.POST("/auth/token/refresh", { body: {} });
    const locks = (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
    if (locks !== undefined) {
        return locks.request(REFRESH_LOCK, refresh);
    }
    if (inFlight === null) {
        inFlight = refresh().finally(() => {
            inFlight = null;
        });
    }

    return inFlight;
}
