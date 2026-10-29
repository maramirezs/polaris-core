<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Tests\Functional;

use Override;
use Polaris\MultiSession\Http\DeviceMiddleware;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\Tests\Functional\CookieDelivery;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_column;
use function array_filter;
use function array_values;
use function str_starts_with;

/**
 * `polaris/multi-session` in cookie token delivery (docs/cookie-mode/spec.md §5): a sign-in is still recorded
 * against the device (its middleware reads the body before the refresh token leaves it), the device cookie
 * travels next to the refresh cookie, and `POST /multi-session/switch` sets the target session's cookie.
 */
final class CookieDeliveryTest extends FunctionalTestCase
{
    use CookieDelivery;

    #[Override]
    protected static function plugins(): array
    {
        return [new MultiSessionPlugin()];
    }

    public function testSignInsJoinTheDeviceAndSwitchingSetsTheCookie(): void
    {
        $this->signUp('ada@example.com');
        $this->signUp('grace@example.com');

        $ada = $this->login('ada@example.com');
        $this->assertSetsRefreshCookie($ada);
        self::assertCount(1, $this->deviceCookies($ada), 'the device cookie is kept next to the refresh cookie');
        $device = $ada->getHeaderLine(DeviceMiddleware::HEADER);
        self::assertNotSame('', $device, 'the sign-in was recorded against a device');
        $grace = $this->login('grace@example.com', $device);
        $device = $grace->getHeaderLine(DeviceMiddleware::HEADER);
        $graceAccess = (string) $this->cookieData($grace)['access_token'];

        $list = $this->json($this->handle($this->browser('GET', '/multi-session/list', token: $graceAccess, headers: [DeviceMiddleware::HEADER => $device])))['data'];
        self::assertSame(['grace@example.com', 'ada@example.com'], array_column(array_column($list, 'user'), 'email'));

        $switched = $this->handle($this->browser('POST', '/multi-session/switch', ['session_id' => (string) $list[1]['session_id']], token: $graceAccess, headers: [DeviceMiddleware::HEADER => $device]));
        self::assertSame(200, $switched->getStatusCode());
        self::assertSame('ada@example.com', $this->cookieData($switched)['user']['email']);
        $this->assertSetsRefreshCookie($switched);
    }

    private function login(string $email, ?string $device = null): ResponseInterface
    {
        return $this->handle($this->browser('POST', '/auth/login', ['email' => $email, 'password' => 'correct horse battery staple'], headers: $device === null ? [] : [DeviceMiddleware::HEADER => $device]));
    }

    /**
     * @return list<string>
     */
    private function deviceCookies(ResponseInterface $response): array
    {
        return array_values(array_filter($response->getHeader('Set-Cookie'), static fn(string $line): bool => str_starts_with($line, DeviceMiddleware::COOKIE . '=')));
    }
}
