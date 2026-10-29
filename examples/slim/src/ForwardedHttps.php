<?php

declare(strict_types=1);

namespace PolarisDemo;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function in_array;
use function strtolower;

/**
 * The demo's trusted-proxy handling: a TLS-terminating proxy on this machine forwards `X-Forwarded-Proto: https`,
 * and the request gets the `https` URI the browser used, which cookie token delivery checks (docs/cookie-mode/
 * spec.md §2.6). A real Slim host does the same for its own proxies, never for an arbitrary client.
 */
final class ForwardedHttps implements MiddlewareInterface
{
    private const array LOOPBACK = ['127.0.0.1', '::1'];

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $peer = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        if (in_array($peer, self::LOOPBACK, true) && strtolower($request->getHeaderLine('X-Forwarded-Proto')) === 'https') {
            $request = $request->withUri($request->getUri()->withScheme('https'));
        }

        return $handler->handle($request);
    }
}
