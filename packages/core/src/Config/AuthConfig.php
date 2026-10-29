<?php

declare(strict_types=1);

namespace Polaris\Config;

use Polaris\Exception\InvalidConfigException;

use function implode;
use function in_array;
use function is_array;
use function is_string;
use function parse_url;
use function strtolower;

/**
 * The typed, validated root of Polaris configuration.
 *
 * Built once at boot from the host's `auth` config namespace (with safe defaults
 * for everything) and bound in the container. Domain services depend on this
 * value object, never on raw arrays. Construction validates every invariant so an
 * invalid configuration fails fast instead of surfacing as a runtime surprise.
 */
final readonly class AuthConfig
{
    private const PASSWORD_ALGOS = ['argon2id', 'argon2i', 'bcrypt'];
    private const TOKEN_DELIVERY = ['body', 'cookie'];

    public function __construct(
        public string $issuer,
        public ?string $audience,
        public AccessTokenConfig $accessToken,
        public RefreshTokenConfig $refreshToken,
        public OtpConfig $otp,
        public int $passwordMinLength,
        public string $passwordAlgo,
        public bool $breachCheck,
        public int $lockoutMaxAttempts,
        public int $lockoutWindow,
        public int $lockoutDuration,
        public bool $mfaEnforce,
        public bool $mfaGraceEnroll,
        public int $mfaLoginTokenTtl,
        public int $stepUpMaxAge,
        public bool $requireVerifiedEmail,
        public string $tokenDelivery,
        /**
         * Origins besides the request's own allowed to sign in and refresh in cookie delivery, normalised to
         * `https://host[:port]` (docs/cookie-mode/spec.md §2.5, §3).
         *
         * @var list<string>
         */
        public array $cookieTrustedOrigins = [],
    ) {
        if ($issuer === '') {
            throw new InvalidConfigException('auth.issuer must be a non-empty string.');
        }

        if ($passwordMinLength < 8) {
            throw new InvalidConfigException('auth.password.min_length must be at least 8.');
        }

        if (!in_array($passwordAlgo, self::PASSWORD_ALGOS, true)) {
            throw new InvalidConfigException(
                'auth.password.algo must be one of: ' . implode(', ', self::PASSWORD_ALGOS) . '.',
            );
        }

        if ($lockoutMaxAttempts <= 0 || $lockoutWindow <= 0 || $lockoutDuration <= 0) {
            throw new InvalidConfigException('auth.lockout values must be positive integers.');
        }

        if ($mfaLoginTokenTtl <= 0) {
            throw new InvalidConfigException('auth.mfa.login_token_ttl must be a positive integer.');
        }

        if ($stepUpMaxAge <= 0) {
            throw new InvalidConfigException('auth.step_up.max_age must be a positive integer.');
        }

        if (!in_array($tokenDelivery, self::TOKEN_DELIVERY, true)) {
            throw new InvalidConfigException(
                'auth.flows.token_delivery must be one of: ' . implode(', ', self::TOKEN_DELIVERY) . '.',
            );
        }

        foreach ($cookieTrustedOrigins as $origin) {
            if (self::origin($origin) !== $origin) {
                throw new InvalidConfigException('auth.flows.cookie.trusted_origins entries must be https://host[:port] origins, got "' . $origin . '".');
            }
        }
    }

    /**
     * An `https` origin as a browser sends it in `Origin` (lower case, no default port), or null when the value is
     * not one: a path, a query, credentials or another scheme make it something else.
     */
    public static function origin(string $value): ?string
    {
        $parts = parse_url($value);
        if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '') {
            return null;
        }
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) || ($parts['path'] ?? '') !== '') {
            return null;
        }
        $port = $parts['port'] ?? null;

        return 'https://' . strtolower($parts['host']) . ($port === null || $port === 443 ? '' : ':' . $port);
    }

    /**
     * @param array<string, mixed> $auth the host's `auth` config namespace
     */
    public static function fromArray(array $auth): self
    {
        $password = self::section($auth, 'password');
        $lockout = self::section($auth, 'lockout');
        $mfa = self::section($auth, 'mfa');
        $flows = self::section($auth, 'flows');
        $stepUp = self::section($auth, 'step_up');

        return new self(
            issuer: (string) ($auth['issuer'] ?? ''),
            audience: self::nullableString($auth['audience'] ?? null),
            accessToken: AccessTokenConfig::fromArray(self::section($auth, 'access_token')),
            refreshToken: RefreshTokenConfig::fromArray(self::section($auth, 'refresh_token')),
            otp: OtpConfig::fromArray(self::section($auth, 'otp')),
            passwordMinLength: (int) ($password['min_length'] ?? 12),
            passwordAlgo: (string) ($password['algo'] ?? 'argon2id'),
            breachCheck: (bool) ($password['breach_check'] ?? false),
            lockoutMaxAttempts: (int) ($lockout['max_attempts'] ?? 5),
            lockoutWindow: (int) ($lockout['window'] ?? 900),
            lockoutDuration: (int) ($lockout['lock_duration'] ?? 900),
            mfaEnforce: (bool) ($mfa['enforce'] ?? false),
            mfaGraceEnroll: (bool) ($mfa['grace_enroll'] ?? true),
            mfaLoginTokenTtl: (int) ($mfa['login_token_ttl'] ?? 300),
            stepUpMaxAge: (int) ($stepUp['max_age'] ?? 300),
            requireVerifiedEmail: (bool) ($flows['require_verified_email'] ?? true),
            tokenDelivery: (string) ($flows['token_delivery'] ?? 'body'),
            cookieTrustedOrigins: self::origins(self::section($flows, 'cookie')['trusted_origins'] ?? []),
        );
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private static function section(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        return is_array($value) ? $value : [];
    }

    /**
     * The configured trusted origins, normalised; an entry that is not an origin is kept as given so the
     * constructor names it.
     *
     * @return list<string>
     */
    private static function origins(mixed $values): array
    {
        if (!is_array($values)) {
            throw new InvalidConfigException('auth.flows.cookie.trusted_origins must be a list of origins.');
        }
        $origins = [];
        foreach ($values as $value) {
            if (!is_string($value)) {
                throw new InvalidConfigException('auth.flows.cookie.trusted_origins must be a list of origins.');
            }
            $origins[] = self::origin($value) ?? $value;
        }

        return $origins;
    }

    private static function nullableString(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string) $value;
    }
}
