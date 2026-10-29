<?php

declare(strict_types=1);

namespace Polaris\Anonymous\Tests\Functional;

use Override;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\Tests\Functional\CookieDelivery;
use Polaris\Tests\Functional\FunctionalTestCase;

use function array_keys;

/**
 * `POST /anonymous/sign-in` in cookie token delivery (docs/cookie-mode/spec.md §5): a guest's refresh token goes
 * to the cookie like any other session's.
 */
final class CookieDeliveryTest extends FunctionalTestCase
{
    use CookieDelivery;

    #[Override]
    protected static function plugins(): array
    {
        return [new AnonymousPlugin()];
    }

    public function testAGuestSessionSetsTheCookie(): void
    {
        $guest = $this->handle($this->browser('POST', '/anonymous/sign-in'));
        self::assertSame(201, $guest->getStatusCode());
        self::assertSame(['access_token', 'token_type', 'expires_in', 'user'], array_keys($this->cookieData($guest)));
        $secret = $this->assertSetsRefreshCookie($guest);

        $refreshed = $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret));
        self::assertSame(200, $refreshed->getStatusCode(), 'the guest refreshes with the cookie');
    }
}
