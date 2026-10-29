/*
 * The TLS-terminating proxy of the cookie-delivery e2e: `node e2e/tls-proxy.mjs <listen port> <upstream port>`
 * serves https://localhost:<listen port> with a throwaway self-signed certificate (openssl) and forwards every
 * request to PHP's built-in server on 127.0.0.1:<upstream port> with `X-Forwarded-Proto: https`, which the Slim
 * demo's ForwardedHttps middleware turns back into an https URI. php -S speaks no TLS, and cookie delivery
 * refuses plaintext.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [listen = "8443", upstream = "8091"] = process.argv.slice(2);
const dir = mkdtempSync(join(tmpdir(), "polaris-tls-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });

createServer({ key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) }, (incoming, outgoing) => {
    const forwarded = request(
        { host: "127.0.0.1", port: Number(upstream), method: incoming.method, path: incoming.url, headers: { ...incoming.headers, "x-forwarded-proto": "https" } },
        (answer) => {
            outgoing.writeHead(answer.statusCode ?? 502, answer.headers);
            answer.pipe(outgoing);
        },
    );
    forwarded.on("error", (error) => {
        outgoing.writeHead(502, { "Content-Type": "text/plain" });
        outgoing.end(String(error));
    });
    incoming.pipe(forwarded);
}).listen(Number(listen), "127.0.0.1", () => {
    console.log(`https://localhost:${listen} -> http://127.0.0.1:${upstream}`);
});
