<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Polaris\Event\UserRegistered;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function abs;
use function array_key_exists;
use function array_key_last;
use function array_map;
use function array_shift;
use function explode;
use function http_build_query;
use function in_array;
use function is_string;
use function parse_str;
use function parse_url;
use function strtolower;

use const PHP_URL_QUERY;

/**
 * Cookie token delivery in a functional suite (docs/cookie-mode/spec.md §5): the class boots with
 * `flows.token_delivery: cookie`, sends browser requests (https, its own `Origin`, the CSRF header, the cookie as a
 * cookie param, which is what every host reads) and reads `Set-Cookie` back as a name, a value and attributes,
 * since Laravel and Symfony re-serialise the header (lower-case attributes, an added `expires`). These tests
 * record no contract fixtures; the body-mode suite keeps those.
 */
trait CookieDelivery
{
    protected const string BROWSER_ORIGIN = 'https://localhost';

    /**
     * @return array<string, mixed>
     */
    protected static function authConfig(): array
    {
        return ['flows' => ['token_delivery' => 'cookie']];
    }

    /**
     * A same-origin browser request over https; `$headers` adds or (with null) removes headers.
     *
     * @param array<string, mixed> $body
     * @param array<string, string|null> $headers
     */
    protected function browser(string $method, string $path, array $body = [], ?string $cookie = null, ?string $token = null, array $headers = [], string $origin = self::BROWSER_ORIGIN): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $origin . $path)
            ->withHeader('Origin', $origin)
            ->withHeader(RefreshCookieMiddleware::CSRF_HEADER, '1');
        $query = parse_url($path, PHP_URL_QUERY);
        if (is_string($query) && $query !== '') {
            parse_str($query, $params);
            $request = $request->withQueryParams($params);
        }
        if ($method !== 'GET') {
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
        }
        if ($cookie !== null) {
            $request = $request->withCookieParams([RefreshCookieMiddleware::COOKIE => $cookie]);
        }
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        foreach ($headers as $name => $value) {
            $request = $value === null ? $request->withoutHeader($name) : $request->withHeader($name, $value);
        }

        return $request;
    }

    /**
     * Registers and verifies the user, then signs in from the browser; their access token.
     */
    protected function signUp(string $email, string $password = 'correct horse battery staple'): string
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => $password]);
        $registered = $this->events->ofType(UserRegistered::class);
        $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
        $this->unitOfWork->clear();
        $login = $this->handle($this->browser('POST', '/auth/login', ['email' => $email, 'password' => $password]));
        $this->assertSetsRefreshCookie($login);

        return (string) $this->cookieData($login)['access_token'];
    }

    /**
     * A plain HTML form post, as a page on another site can send one: form-encoded bytes, no CSRF header.
     *
     * @param array<string, string> $fields
     */
    protected function formPost(string $path, array $fields, string $origin): ServerRequestInterface
    {
        $encoded = http_build_query($fields);
        $request = (new ServerRequestFactory())->createServerRequest('POST', self::BROWSER_ORIGIN . $path);
        $query = parse_url($path, PHP_URL_QUERY);
        if (is_string($query) && $query !== '') {
            parse_str($query, $params);
            $request = $request->withQueryParams($params);
        }

        return $request
            ->withHeader('Origin', $origin)
            ->withHeader('Sec-Fetch-Site', 'cross-site')
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody((new StreamFactory())->createStream($encoded))
            ->withParsedBody($fields);
    }

    /**
     * The refresh cookie a response sets, or null.
     *
     * @return array{value: string, attributes: array<string, string>}|null
     */
    protected function refreshCookie(ResponseInterface $response): ?array
    {
        foreach ($response->getHeader('Set-Cookie') as $line) {
            $parts = array_map('trim', explode(';', $line));
            [$name, $value] = explode('=', (string) array_shift($parts), 2) + [1 => ''];
            if ($name !== RefreshCookieMiddleware::COOKIE) {
                continue;
            }
            $attributes = [];
            foreach ($parts as $part) {
                [$key, $attribute] = explode('=', $part, 2) + [1 => ''];
                $attributes[strtolower($key)] = $attribute;
            }

            return ['value' => $value, 'attributes' => $attributes];
        }

        return null;
    }

    /**
     * The response sets the refresh cookie with the attributes of spec §2.4; returns its secret.
     */
    protected function assertSetsRefreshCookie(ResponseInterface $response, string $path = '/auth/token/refresh'): string
    {
        $cookie = $this->refreshCookie($response);
        self::assertNotNull($cookie, 'the response sets the refresh cookie');
        self::assertNotSame('', $cookie['value']);
        $attributes = $cookie['attributes'];
        self::assertSame($path, $attributes['path'] ?? null);
        // A host that re-serialises the cookie recomputes Max-Age from its expiry, a second or two apart.
        self::assertLessThanOrEqual(2, abs((int) ($attributes['max-age'] ?? 0) - $this->graph->config()->auth->refreshToken->ttl));
        self::assertTrue(array_key_exists('httponly', $attributes) && array_key_exists('secure', $attributes), 'HttpOnly and Secure');
        self::assertSame('strict', strtolower($attributes['samesite'] ?? ''));
        self::assertArrayNotHasKey('domain', $attributes, 'host-only');

        return $cookie['value'];
    }

    protected function assertClearsRefreshCookie(ResponseInterface $response): void
    {
        $cookie = $this->refreshCookie($response);
        self::assertNotNull($cookie, 'the response clears the refresh cookie');
        // Symfony's HttpFoundation renders an emptied cookie as `deleted` with a past expiry.
        self::assertTrue(in_array($cookie['value'], ['', 'deleted'], true));
        self::assertSame('0', $cookie['attributes']['max-age'] ?? null);
    }

    protected function assertNoRefreshCookie(ResponseInterface $response): void
    {
        self::assertNull($this->refreshCookie($response), 'the response leaves the refresh cookie alone');
    }

    /**
     * The `data` of a cookie-delivery success: no `refresh_token`.
     *
     * @return array<string, mixed>
     */
    protected function cookieData(ResponseInterface $response): array
    {
        $data = $this->json($response)['data'] ?? null;
        self::assertIsArray($data);
        self::assertArrayNotHasKey('refresh_token', $data, 'the refresh token is not in the body');
        self::assertIsString($data['access_token'] ?? null);

        return $data;
    }
}
