<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Http\Attributes;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Result;
use Polaris\Psr15\JsonResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function sprintf;
use function strtolower;
use function trim;

use const JSON_THROW_ON_ERROR;

/**
 * Cookie token delivery (`auth.flows.token_delivery: cookie`, docs/cookie-mode/spec.md §2.3): on the routes whose
 * spec has `session`, the refresh token travels in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to the
 * refresh route instead of the JSON body. Registered only in cookie delivery, right after the per-IP limiter, so
 * every middleware and endpoint behind it sees requests and responses exactly as body delivery produces them.
 *
 * `issue` and `refresh` routes refuse plaintext and pass the CSRF guard (§2.5) before the handler; a refresh
 * that carries no `refresh_token` of its own takes the cookie's; a 200 or 201 carrying `data.refresh_token`
 * loses the key to the cookie. A 401 on a refresh that the cookie authenticated, and a 2xx on an `end` route,
 * clear the cookie.
 */
final class RefreshCookieMiddleware implements MiddlewareInterface
{
    public const string COOKIE = '__Secure-polaris_refresh';
    public const string CSRF_HEADER = 'X-Polaris-CSRF';
    private const string FIELD = 'refresh_token';

    /**
     * @param string $path the refresh route's path as the router mounts it (the cookie's `Path`)
     * @param int $maxAge the cookie's `Max-Age`: `refresh_token.ttl`
     * @param list<string> $trustedOrigins origins besides the request's own that may sign in and refresh
     */
    public function __construct(
        private readonly string $path,
        private readonly int $maxAge,
        private readonly array $trustedOrigins,
        private readonly ResponseFactoryInterface $responses,
        private readonly JsonResponse $json,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || $spec->session === null) {
            return $handler->handle($request);
        }
        if ($spec->session === 'end') {
            $response = $handler->handle($request);

            return $response->getStatusCode() >= 200 && $response->getStatusCode() < 300 ? $response->withAddedHeader('Set-Cookie', $this->cookie('', 0)) : $response;
        }

        if (strtolower($request->getUri()->getScheme()) !== 'https') {
            return $this->refuse($spec, 'insecure_transport', 'Insecure transport', 'Cookie token delivery requires HTTPS.');
        }
        if (!$this->guarded($request)) {
            return $this->refuse($spec, 'csrf_failed', 'CSRF check failed', 'The request failed the CSRF check.');
        }

        $fromCookie = false;
        if ($spec->session === 'refresh') {
            [$request, $fromCookie] = $this->presentCookie($request);
        }
        $response = $handler->handle($request);
        $status = $response->getStatusCode();
        if ($status === 401 && $fromCookie) {
            return $response->withAddedHeader('Set-Cookie', $this->cookie('', 0));
        }

        return $status === 200 || $status === 201 ? $this->moveToCookie($response) : $response;
    }

    /**
     * The guard of §2.5: the custom header (a cross-origin page cannot send it without a preflight Polaris never
     * answers), and the request's own origin or a trusted one in `Origin` or, without it, `Sec-Fetch-Site`.
     */
    private function guarded(ServerRequestInterface $request): bool
    {
        if (trim($request->getHeaderLine(self::CSRF_HEADER)) !== '1') {
            return false;
        }
        $origin = strtolower(trim($request->getHeaderLine('Origin')));
        if ($origin !== '') {
            return $origin === self::ownOrigin($request) || in_array($origin, $this->trustedOrigins, true);
        }
        $site = strtolower(trim($request->getHeaderLine('Sec-Fetch-Site')));

        return $site === '' || $site === 'same-origin';
    }

    private static function ownOrigin(ServerRequestInterface $request): string
    {
        $uri = $request->getUri();
        $port = $uri->getPort();

        return strtolower($uri->getScheme() . '://' . $uri->getHost()) . ($port === null ? '' : ':' . $port);
    }

    /**
     * The cookie's secret as the refresh's `refresh_token`, unless the request carries one of its own in any
     * source the endpoint reads (body, query).
     *
     * @return array{ServerRequestInterface, bool} the request and whether the cookie is its credential
     */
    private function presentCookie(ServerRequestInterface $request): array
    {
        $own = Input::fromServerRequest($request)->get(self::FIELD);
        if (is_string($own) && trim($own) !== '') {
            return [$request, false];
        }
        $cookie = $request->getCookieParams()[self::COOKIE] ?? null;
        $body = $request->getParsedBody() ?? [];
        if (!is_string($cookie) || $cookie === '' || !is_array($body)) {
            return [$request, false];
        }

        return [$request->withParsedBody([...$body, self::FIELD => $cookie]), true];
    }

    /**
     * A success carrying `data.refresh_token`: the key leaves the body, re-encoded as {@see JsonResponse} encodes
     * (decoded to objects, so an empty object stays one), and the secret goes to the cookie. Anything else (an
     * `mfa_required` ticket) passes unchanged.
     */
    private function moveToCookie(ResponseInterface $response): ResponseInterface
    {
        $raw = (string) $response->getBody();
        $response->getBody()->rewind();
        $body = json_decode($raw, false);
        if (!$body instanceof stdClass || !($body->data ?? null) instanceof stdClass || !is_string($body->data->{self::FIELD} ?? null)) {
            return $response;
        }
        $secret = $body->data->{self::FIELD};
        unset($body->data->{self::FIELD});
        $stream = $this->responses->createResponse()->getBody();
        $stream->write(json_encode($body, JSON_THROW_ON_ERROR));

        return $response
            ->withBody($stream)
            ->withoutHeader('Content-Length')
            ->withAddedHeader('Set-Cookie', $this->cookie($secret, $this->maxAge));
    }

    /**
     * The refresh cookie (§2.4); an empty secret with `Max-Age=0` clears it.
     */
    private function cookie(string $secret, int $maxAge): string
    {
        return sprintf('%s=%s; Path=%s; Max-Age=%d; HttpOnly; Secure; SameSite=Strict', self::COOKIE, $secret, $this->path, $maxAge);
    }

    /**
     * A refusal in the envelope of the route it refuses: core's `{error, message}`, a plugin's problem document.
     */
    private function refuse(EndpointSpec $spec, string $code, string $title, string $message): ResponseInterface
    {
        if ($spec->plugin === null) {
            return $this->json->error(403, $code, $message);
        }

        return $this->json->result(new Result(403, [
            'type' => Endpoint::PROBLEM_TYPES . $code,
            'title' => $title,
            'status' => 403,
            'detail' => $message,
            'error' => $code,
            'message' => $message,
        ], problem: true));
    }
}
