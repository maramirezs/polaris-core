<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Functional;

use Polaris\Sso\Tests\Support\FakeSaml;
use Polaris\Tests\Functional\CookieDelivery;

use function parse_str;
use function parse_url;

use const PHP_URL_QUERY;

/**
 * `POST /sso/exchange` and `POST /sso/logout` in cookie token delivery (docs/cookie-mode/spec.md §5): the exchange
 * sets the cookie, single logout clears it.
 */
final class CookieDeliveryTest extends SsoTestCase
{
    use CookieDelivery;

    public function testTheExchangeSetsTheCookieAndSingleLogoutClearsIt(): void
    {
        $ada = $this->signUp('ada@acme.example');
        [$acme, $owner] = $this->organization('Acme Rockets', $ada);
        $saml = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers', $this->samlProvider(), $owner))['data'];
        $this->postJson('/sso/sign-in', ['provider_id' => $saml['id']]);
        $acs = $this->postJson('/sso/callback/' . $saml['id'], ['SAMLResponse' => 'good:carol@acme.example', 'RelayState' => (string) FakeSaml::$lastRelayState]);
        self::assertSame(302, $acs->getStatusCode());

        $exchanged = $this->handle($this->browser('POST', '/sso/exchange', ['code' => self::param($acs->getHeaderLine('Location'), 'sso_code')]));
        self::assertSame(200, $exchanged->getStatusCode(), (string) $exchanged->getBody());
        $carol = $this->cookieData($exchanged);
        self::assertSame('carol@acme.example', $carol['user']['email']);
        $secret = $this->assertSetsRefreshCookie($exchanged);

        $logout = $this->handle($this->browser('POST', '/sso/logout', ['provider_id' => $saml['id']], token: (string) $carol['access_token']));
        self::assertSame(200, $logout->getStatusCode());
        $this->assertClearsRefreshCookie($logout);
        self::assertSame(401, $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret))->getStatusCode());
    }

    private static function param(string $url, string $name): string
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query[$name] ?? '');
    }
}
