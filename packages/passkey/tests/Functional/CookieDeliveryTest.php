<?php

declare(strict_types=1);

namespace Polaris\Passkey\Tests\Functional;

use Polaris\Passkey\Tests\Support\SoftwareAuthenticator;
use Polaris\Tests\Functional\CookieDelivery;

use function json_decode;

/**
 * `POST /passkey/authenticate/verify` in cookie token delivery (docs/cookie-mode/spec.md §5).
 */
final class CookieDeliveryTest extends PasskeyTestCase
{
    use CookieDelivery;

    public function testSigningInWithAPasskeySetsTheCookie(): void
    {
        $access = $this->signUp('ada@example.com');
        $authenticator = new SoftwareAuthenticator();
        $options = $this->json($this->authedPostJson('/passkey/register/options', [], $access))['data'];
        self::assertSame(201, $this->authedPostJson('/passkey/register/verify', ['credential' => json_decode($authenticator->create($options, self::ORIGIN), true)], $access)->getStatusCode());
        $me = $this->json($this->authedGet('/auth/me', $access))['data'];

        $request = $this->json($this->postJson('/passkey/authenticate/options', []))['data'];
        $signedIn = $this->handle($this->browser('POST', '/passkey/authenticate/verify', ['credential' => json_decode($authenticator->get($request, self::ORIGIN, (string) $me['id'], counter: 1), true)]));
        self::assertSame(200, $signedIn->getStatusCode());
        self::assertSame('ada@example.com', $this->cookieData($signedIn)['user']['email']);
        $this->assertSetsRefreshCookie($signedIn);
    }
}
