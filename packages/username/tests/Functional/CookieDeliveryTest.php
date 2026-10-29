<?php

declare(strict_types=1);

namespace Polaris\Username\Tests\Functional;

use Override;
use Polaris\Tests\Functional\CookieDelivery;
use Polaris\Tests\Functional\FunctionalTestCase;
use Polaris\Username\UsernamePlugin;

/**
 * `POST /username/sign-in` in cookie token delivery (docs/cookie-mode/spec.md §5): the refresh token goes to the
 * cookie, and a refusal on a plugin route is a problem document.
 */
final class CookieDeliveryTest extends FunctionalTestCase
{
    use CookieDelivery;

    #[Override]
    protected static function plugins(): array
    {
        return [new UsernamePlugin()];
    }

    public function testSigningInWithAUsernameSetsTheCookie(): void
    {
        $access = $this->signUp('ada@example.com');
        $this->authedPatch('/username', ['username' => 'ada.l'], $access);

        $signedIn = $this->handle($this->browser('POST', '/username/sign-in', ['username' => 'ada.l', 'password' => 'correct horse battery staple']));
        self::assertSame(200, $signedIn->getStatusCode());
        self::assertSame('ada@example.com', $this->cookieData($signedIn)['user']['email']);
        $this->assertSetsRefreshCookie($signedIn);
    }

    public function testARefusalOnAPluginRouteIsAProblemDocument(): void
    {
        $plaintext = $this->handle($this->browser('POST', '/username/sign-in', ['username' => 'ada.l', 'password' => 'x'], origin: 'http://localhost'));
        self::assertSame(403, $plaintext->getStatusCode());
        self::assertSame('application/problem+json', $plaintext->getHeaderLine('Content-Type'));
        self::assertSame([
            'type' => 'https://polaris.univeros.io/problems/insecure_transport',
            'title' => 'Insecure transport',
            'status' => 403,
            'detail' => 'Cookie token delivery requires HTTPS.',
            'error' => 'insecure_transport',
            'message' => 'Cookie token delivery requires HTTPS.',
        ], $this->json($plaintext));

        $forged = $this->handle($this->formPost('/username/sign-in', ['username' => 'ada.l', 'password' => 'x'], 'https://evil.example'));
        self::assertSame([403, 'csrf_failed'], [$forged->getStatusCode(), $this->json($forged)['error']]);
        $this->assertNoRefreshCookie($forged);
    }
}
