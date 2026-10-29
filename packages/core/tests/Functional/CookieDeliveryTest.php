<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use OTPHP\TOTP;
use Override;
use Polaris\Event\UserRegistered;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Psr\Http\Message\ResponseInterface;

use function array_keys;
use function time;

/**
 * Core's session routes in cookie token delivery (docs/cookie-mode/spec.md §5), through the pipeline and, with
 * `POLARIS_HARNESS`, through every host: the refresh token moves to the cookie, the cookie refreshes behind the
 * CSRF guard, the guard also covers sign-in (login CSRF), logout clears the cookie, plaintext is refused.
 */
final class CookieDeliveryTest extends FunctionalTestCase
{
    use CookieDelivery;

    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string TRUSTED = 'https://app.localhost';

    #[Override]
    protected static function authConfig(): array
    {
        return ['flows' => ['token_delivery' => 'cookie', 'cookie' => ['trusted_origins' => [self::TRUSTED]]]];
    }

    public function testLoginPutsTheRefreshTokenInTheCookieAndNotTheBody(): void
    {
        $this->register();
        $response = $this->login();

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['access_token', 'token_type', 'expires_in', 'user'], array_keys($this->cookieData($response)), 'every other field as in body mode');
        $this->assertSetsRefreshCookie($response);
        self::assertCount(1, $response->getHeader('Set-Cookie'));
    }

    public function testTheMfaTicketSetsNoCookieAndVerifySetsIt(): void
    {
        $this->register();
        $access = (string) $this->cookieData($this->login())['access_token'];
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $this->authedPostJson('/auth/mfa/totp/confirm', ['factor_id' => $enroll['factor_id'], 'code' => $this->totp((string) $enroll['secret'])->now()], $access);
        $this->unitOfWork->clear();

        $ticket = $this->login();
        self::assertSame(200, $ticket->getStatusCode());
        $challenge = $this->json($ticket)['data'];
        self::assertTrue($challenge['mfa_required']);
        $this->assertNoRefreshCookie($ticket);

        $verified = $this->handle($this->browser('POST', '/auth/mfa/verify', [
            'factor_id' => $challenge['factors'][0]['id'],
            'code' => $this->totp((string) $enroll['secret'])->at(time() + 30),
        ], token: (string) $challenge['mfa_token']));
        self::assertSame(200, $verified->getStatusCode());
        $this->cookieData($verified);
        $this->assertSetsRefreshCookie($verified);
    }

    public function testTheCookieRefreshesAndRotates(): void
    {
        $this->register();
        $first = $this->assertSetsRefreshCookie($this->login());

        $refreshed = $this->refresh($first);
        self::assertSame(200, $refreshed->getStatusCode());
        self::assertSame(['access_token', 'token_type', 'expires_in'], array_keys($this->cookieData($refreshed)));
        $second = $this->assertSetsRefreshCookie($refreshed);
        self::assertNotSame($first, $second);
        self::assertSame(200, $this->authedGet('/auth/me', (string) $this->json($refreshed)['data']['access_token'])->getStatusCode());
    }

    public function testTheGuardRefusesARefreshWithoutTheHeaderOrFromAnotherOriginAndConsumesNothing(): void
    {
        $this->register();
        $secret = $this->assertSetsRefreshCookie($this->login());

        $cases = [
            'no header' => [RefreshCookieMiddleware::CSRF_HEADER => null],
            'a foreign Origin' => ['Origin' => 'https://evil.example'],
            'Origin: null' => ['Origin' => 'null'],
            'a sibling origin not trusted' => ['Origin' => 'https://other.localhost'],
            'Sec-Fetch-Site: cross-site' => ['Origin' => null, 'Sec-Fetch-Site' => 'cross-site'],
            'Sec-Fetch-Site: same-site' => ['Origin' => null, 'Sec-Fetch-Site' => 'same-site'],
        ];
        foreach ($cases as $case => $headers) {
            $refused = $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret, headers: $headers));
            self::assertSame(403, $refused->getStatusCode(), $case);
            self::assertSame(['error' => 'csrf_failed', 'message' => 'The request failed the CSRF check.'], $this->json($refused), $case);
            $this->assertNoRefreshCookie($refused);
        }

        self::assertSame(200, $this->refresh($secret)->getStatusCode(), 'the token was not consumed');
    }

    public function testATrustedOriginAndAMissingOriginWithSameOriginFetchMetadataPass(): void
    {
        $this->register();
        $secret = $this->assertSetsRefreshCookie($this->login());

        $trusted = $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret, headers: ['Origin' => self::TRUSTED]));
        self::assertSame(200, $trusted->getStatusCode());
        $secret = $this->assertSetsRefreshCookie($trusted);

        $sameOrigin = $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret, headers: ['Origin' => null, 'Sec-Fetch-Site' => 'same-origin']));
        self::assertSame(200, $sameOrigin->getStatusCode());
    }

    public function testACrossSiteFormCannotPlantASession(): void
    {
        $this->register();
        $rows = $this->graph->database()->count('auth_refresh_tokens', []);

        $login = $this->handle($this->formPost('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD], 'https://evil.example'));
        self::assertSame(403, $login->getStatusCode());
        self::assertSame('csrf_failed', $this->json($login)['error']);
        $this->assertNoRefreshCookie($login);
        self::assertSame($rows, $this->graph->database()->count('auth_refresh_tokens', []), 'no session was opened');

        // An attacker's own refresh token, in the query or in the form, is refused the same way and stays valid.
        $mine = $this->assertSetsRefreshCookie($this->login());
        $forged = [
            $this->formPost('/auth/token/refresh?refresh_token=' . $mine, [], 'https://evil.example'),
            $this->formPost('/auth/token/refresh', ['refresh_token' => $mine], 'https://evil.example'),
        ];
        foreach ($forged as $request) {
            $refused = $this->handle($request);
            self::assertSame(403, $refused->getStatusCode());
            $this->assertNoRefreshCookie($refused);
        }
        self::assertSame(200, $this->refresh($mine)->getStatusCode());
    }

    public function testABodyTokenStillRefreshesIntoTheCookieAndABadOneLeavesTheCookieAlone(): void
    {
        $this->register();
        $cookie = $this->assertSetsRefreshCookie($this->login());
        $other = $this->assertSetsRefreshCookie($this->login());

        // A session that still holds a body token moves into the cookie on its next refresh (spec §8, question 3).
        $migrated = $this->handle($this->browser('POST', '/auth/token/refresh', ['refresh_token' => $other]));
        self::assertSame(200, $migrated->getStatusCode());
        $this->cookieData($migrated);
        $this->assertSetsRefreshCookie($migrated);

        $failed = $this->handle($this->browser('POST', '/auth/token/refresh', ['refresh_token' => 'not-a-token'], cookie: $cookie));
        self::assertSame(401, $failed->getStatusCode());
        $this->assertNoRefreshCookie($failed);
        self::assertSame(200, $this->refresh($cookie)->getStatusCode(), 'the cookie was not the credential, so it stays valid');
    }

    public function testReplayingARotatedCookieRevokesTheFamilyAndClearsTheCookie(): void
    {
        $this->register();
        $first = $this->assertSetsRefreshCookie($this->login());
        $second = $this->assertSetsRefreshCookie($this->refresh($first));

        $replayed = $this->refresh($first);
        self::assertSame(401, $replayed->getStatusCode());
        self::assertSame('invalid_grant', $this->json($replayed)['error']);
        $this->assertClearsRefreshCookie($replayed);
        self::assertSame(401, $this->refresh($second)->getStatusCode(), 'the whole family is revoked');
    }

    public function testLogoutAndLogoutAllClearTheCookie(): void
    {
        $this->register();
        foreach (['/auth/logout', '/auth/logout-all'] as $route) {
            $login = $this->login();
            $secret = $this->assertSetsRefreshCookie($login);
            $out = $this->handle($this->browser('POST', $route, token: (string) $this->json($login)['data']['access_token']));
            self::assertSame(200, $out->getStatusCode(), $route);
            $this->assertClearsRefreshCookie($out);
            self::assertSame(401, $this->refresh($secret)->getStatusCode(), $route);
        }

        $unauthenticated = $this->handle($this->browser('POST', '/auth/logout'));
        self::assertSame(401, $unauthenticated->getStatusCode());
        $this->assertNoRefreshCookie($unauthenticated);
    }

    public function testPlaintextIsRefusedBeforeASessionOpens(): void
    {
        $this->register();
        $rows = $this->graph->database()->count('auth_refresh_tokens', []);

        $login = $this->handle($this->browser('POST', '/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD], origin: 'http://localhost'));
        self::assertSame(403, $login->getStatusCode());
        self::assertSame(['error' => 'insecure_transport', 'message' => 'Cookie token delivery requires HTTPS.'], $this->json($login));
        $this->assertNoRefreshCookie($login);
        self::assertSame($rows, $this->graph->database()->count('auth_refresh_tokens', []));

        $secret = $this->assertSetsRefreshCookie($this->login());
        $refresh = $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret, origin: 'http://localhost'));
        self::assertSame(403, $refresh->getStatusCode());
        self::assertSame('insecure_transport', $this->json($refresh)['error']);
    }

    private function register(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();
    }

    private function login(): ResponseInterface
    {
        return $this->handle($this->browser('POST', '/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]));
    }

    private function refresh(string $secret): ResponseInterface
    {
        return $this->handle($this->browser('POST', '/auth/token/refresh', cookie: $secret));
    }

    private function totp(string $secret): TOTP
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');

        return $totp;
    }
}
