<?php

declare(strict_types=1);

namespace Polaris\Social\Tests\Functional;

use Polaris\Social\Tests\Support\RecordedProviders;
use Polaris\Tests\Functional\CookieDelivery;
use Psr\Http\Message\ResponseInterface;

/**
 * `POST /social/exchange` and `POST /social/google/one-tap` in cookie token delivery (docs/cookie-mode/spec.md §5).
 */
final class CookieDeliveryTest extends SocialTestCase
{
    use CookieDelivery;

    public function testTheExchangeAfterACallbackSetsTheCookie(): void
    {
        $callback = $this->get('/social/google/callback?code=good&state=' . $this->start('google'));
        self::assertSame(302, $callback->getStatusCode());

        $this->assertSignedIn($this->handle($this->browser('POST', '/social/exchange', ['code' => self::param($callback->getHeaderLine('Location'), 'code')])));
    }

    public function testOneTapSetsTheCookie(): void
    {
        $credential = RecordedProviders::mint('https://accounts.google.com', 'google-client', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, 'Ada Lovelace');

        $this->assertSignedIn($this->handle($this->browser('POST', '/social/google/one-tap', ['credential' => $credential])));
    }

    private function assertSignedIn(ResponseInterface $response): void
    {
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('ada@example.com', $this->cookieData($response)['user']['email']);
        $this->assertSetsRefreshCookie($response);
    }
}
