<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Tests\Functional;

use Polaris\Tests\Functional\CookieDelivery;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;

/**
 * The four passwordless sign-ins in cookie token delivery (docs/cookie-mode/spec.md §5): the magic-link exchange,
 * the email code, the phone code and the one-time token each set the cookie and keep the token out of the body.
 */
final class CookieDeliveryTest extends PasswordlessTestCase
{
    use CookieDelivery;

    public function testAMagicLinkExchangeSetsTheCookie(): void
    {
        $this->postJson('/magic-link/send', ['email' => 'ada@example.com']);
        $link = (string) self::$mail->messages[array_key_last(self::$mail->messages)]->vars['link'];
        $verify = $this->get('/magic-link/verify?token=' . self::param($link, 'token'));
        self::assertSame(302, $verify->getStatusCode());

        $this->assertSignedIn($this->handle($this->browser('POST', '/magic-link/exchange', ['code' => self::param($verify->getHeaderLine('Location'), 'code')])));
    }

    public function testAnEmailCodeSetsTheCookie(): void
    {
        $this->signUp('ada@example.com');
        $this->postJson('/email-otp/send', ['email' => 'ada@example.com']);

        $this->assertSignedIn($this->handle($this->browser('POST', '/email-otp/verify', ['email' => 'ada@example.com', 'code' => self::code(self::$mail)])));
    }

    public function testAPhoneCodeSetsTheCookie(): void
    {
        $access = $this->signUp('ada@example.com');
        $this->authedPostJson('/phone/add', ['phone' => '+15551234567'], $access);
        $this->authedPostJson('/phone/confirm', ['phone' => '+15551234567', 'code' => self::code(self::$phone)], $access);
        $this->postJson('/phone/send', ['phone' => '+15551234567']);

        $this->assertSignedIn($this->handle($this->browser('POST', '/phone/verify', ['phone' => '+15551234567', 'code' => self::code(self::$phone)])));
    }

    public function testAOneTimeTokenSetsTheCookie(): void
    {
        $access = $this->signUp('ada@example.com');
        $generated = $this->json($this->authedPostJson('/one-time-token/generate', [], $access))['data'];

        $this->assertSignedIn($this->handle($this->browser('POST', '/one-time-token/verify', ['token' => (string) $generated['token']])));
    }

    private function assertSignedIn(ResponseInterface $response): void
    {
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('ada@example.com', $this->cookieData($response)['user']['email']);
        $this->assertSetsRefreshCookie($response);
    }
}
