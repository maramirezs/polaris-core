<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Loader;
use Polaris\Polaris;
use Polaris\Psr15\JsonResponse;
use Polaris\Psr15\Middleware\AuthRateLimitMiddleware;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Polaris\Psr15\Pipeline;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionProperty;

use function array_filter;
use function array_keys;
use function array_map;
use function array_search;
use function array_values;
use function str_repeat;

/**
 * The unit side of cookie token delivery (docs/cookie-mode/spec.md §2.3): where the pipeline registers the
 * middleware, and the byte-level rewrite of a success; the flows themselves are in the functional suites.
 */
#[CoversClass(RefreshCookieMiddleware::class)]
#[CoversClass(Pipeline::class)]
final class RefreshCookieMiddlewareTest extends TestCase
{
    public function testThePipelineRegistersItOnlyInCookieDeliveryRightAfterThePerIpLimiter(): void
    {
        self::assertSame([], self::cookieMiddleware(new Pipeline(self::graph('body'), new ResponseFactory())), 'body delivery runs the 0.11 stack');
        self::assertSame([], self::cookieMiddleware(new Pipeline(self::graph('cookie'), new ResponseFactory(), bodyDelivery: true)), 'an in-process caller keeps the body');

        $middleware = (new Pipeline(self::graph('cookie'), new ResponseFactory(), '/api/'))->middleware();
        $classes = array_map(static fn(MiddlewareInterface $m): string => $m::class, $middleware);
        $at = array_search(RefreshCookieMiddleware::class, $classes, true);
        self::assertSame(array_search(AuthRateLimitMiddleware::class, $classes, true) + 1, $at);
        self::assertSame('/api/auth/token/refresh', (new ReflectionProperty(RefreshCookieMiddleware::class, 'path'))->getValue($middleware[$at]), 'the refresh route as the router mounts it');
    }

    public function testARouteWithoutASessionPassesUntouched(): void
    {
        $response = (new ResponseFactory())->createResponse(200);
        $handler = self::answering($response);

        self::assertSame($response, self::middleware()->process(self::request('/auth/me', null), $handler));
    }

    public function testTheTokenLeavesTheBodyByteForByteAndContentLengthGoes(): void
    {
        $body = '{"data":{"access_token":"a.b.c","token_type":"Bearer","expires_in":900,"refresh_token":"secret-1","meta":{},"list":[],"url":"https:\/\/x.example\/p","name":"Ad\u00e1"}}';
        $response = (new ResponseFactory())->createResponse(200)->withHeader('Content-Type', 'application/json')->withHeader('Content-Length', '999');
        $response->getBody()->write($body);

        $moved = self::middleware()->process(self::request('/auth/login', 'issue'), self::answering($response));

        self::assertSame('{"data":{"access_token":"a.b.c","token_type":"Bearer","expires_in":900,"meta":{},"list":[],"url":"https:\/\/x.example\/p","name":"Ad\u00e1"}}', (string) $moved->getBody());
        self::assertFalse($moved->hasHeader('Content-Length'));
        self::assertSame('application/json', $moved->getHeaderLine('Content-Type'));
        self::assertSame(['__Secure-polaris_refresh=secret-1; Path=/auth/token/refresh; Max-Age=600; HttpOnly; Secure; SameSite=Strict'], $moved->getHeader('Set-Cookie'));
    }

    public function testASuccessWithoutARefreshTokenPassesUnchanged(): void
    {
        $response = (new ResponseFactory())->createResponse(200);
        $response->getBody()->write('{"data":{"mfa_required":true,"mfa_token":"t"}}');

        $passed = self::middleware()->process(self::request('/auth/login', 'issue'), self::answering($response));

        self::assertSame('{"data":{"mfa_required":true,"mfa_token":"t"}}', (string) $passed->getBody());
        self::assertFalse($passed->hasHeader('Set-Cookie'));
    }

    /**
     * @return list<MiddlewareInterface>
     */
    private static function cookieMiddleware(Pipeline $pipeline): array
    {
        return array_values(array_filter($pipeline->middleware(), static fn(MiddlewareInterface $m): bool => $m instanceof RefreshCookieMiddleware));
    }

    private static function middleware(): RefreshCookieMiddleware
    {
        return new RefreshCookieMiddleware('/auth/token/refresh', 600, [], new ResponseFactory(), new JsonResponse(new ResponseFactory()));
    }

    private static function request(string $path, ?string $session): ServerRequestInterface
    {
        $core = (new Loader(Loader::defaultDirectory()))->load()->find('POST', '/auth/login');
        self::assertInstanceOf(EndpointSpec::class, $core);
        $values = [];
        foreach (array_keys((array) $core) as $property) {
            $values[$property] = $core->{$property};
        }
        $spec = new EndpointSpec(...[...$values, 'path' => $path, 'session' => $session]);

        return (new ServerRequestFactory())->createServerRequest('POST', 'https://localhost' . $path)
            ->withHeader('Origin', 'https://localhost')
            ->withHeader(RefreshCookieMiddleware::CSRF_HEADER, '1')
            ->withAttribute(Attributes::ROUTE, $spec);
    }

    private static function answering(ResponseInterface $response): RequestHandlerInterface
    {
        return new class ($response) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response)
            {
            }

            #[Override]
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };
    }

    private static function graph(string $delivery): Graph
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test', 'flows' => ['token_delivery' => $delivery]]),
            database: new InMemoryAdapter(),
            pathPrefix: '/api/',
        ))->graph();
    }
}
