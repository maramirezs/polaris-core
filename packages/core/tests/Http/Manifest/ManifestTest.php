<?php

declare(strict_types=1);

namespace Polaris\Tests\Http\Manifest;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Config\RateLimitConfig;
use Polaris\Http\Auth\OtpFactorConfirmEndpoint;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\Manifest\Manifest;
use Polaris\Http\Manifest\OpenApi;
use ReflectionClass;

use function array_count_values;
use function array_filter;
use function array_key_exists;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function bin2hex;
use function class_exists;
use function count;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function glob;
use function in_array;
use function is_array;
use function is_subclass_of;
use function json_decode;
use function lcfirst;
use function mkdir;
use function preg_replace_callback;
use function property_exists;
use function random_bytes;
use function rmdir;
use function sort;
use function str_ends_with;
use function strtoupper;
use function sys_get_temp_dir;
use function unlink;

#[CoversClass(Loader::class)]
#[CoversClass(Manifest::class)]
#[CoversClass(EndpointSpec::class)]
final class ManifestTest extends TestCase
{
    /** Endpoint classes 1.0 already served from more than one route. */
    private const array SHARED = [OtpFactorConfirmEndpoint::class];

    private Manifest $manifest;

    protected function setUp(): void
    {
        $this->manifest = (new Loader(Loader::defaultDirectory()))->load();
    }

    public function testEverySpecShowsItsSuccessBody(): void
    {
        foreach ($this->manifest->endpoints() as $spec) {
            self::assertArrayHasKey('example', $spec->outputExamples, "$spec->file: output.example types the response for the clients");
            foreach ($spec->outputExamples as $key => $example) {
                self::assertNotSame([], $example, "$spec->file: $key");
            }
        }
        $login = $this->manifest->find('POST', '/auth/login');
        self::assertNotNull($login);
        self::assertSame(['example', 'example_mfa_required'], array_keys($login->outputExamples));
    }

    public function testEverySpecRoutesToAnEndpointAndEveryEndpointIsSpecified(): void
    {
        self::assertCount(52, $this->manifest->endpoints());

        $referenced = [];
        foreach ($this->manifest->endpoints() as $spec) {
            self::assertTrue(class_exists($spec->class), "$spec->file: $spec->class");
            self::assertTrue(is_subclass_of($spec->class, Endpoint::class), "$spec->file: $spec->class must extend Endpoint");
            $referenced[] = $spec->class;
        }
        foreach (array_count_values($referenced) as $class => $count) {
            self::assertTrue($count === 1 || in_array($class, self::SHARED, true), "$class is referenced by $count specs");
        }

        $endpoints = [];
        foreach (glob(Loader::defaultDirectory() . '/../src/Http/*/*Endpoint.php') ?: [] as $file) {
            $class = 'Polaris\\Http\\' . basename(dirname($file)) . '\\' . basename($file, '.php');
            if (class_exists($class) && !(new ReflectionClass($class))->isAbstract()) {
                $endpoints[] = $class;
            }
        }
        $unreferenced = array_diff($endpoints, array_unique($referenced));
        self::assertSame([], array_values($unreferenced), 'every Endpoint class is referenced by a spec');
    }

    public function testRoutesAreUniqueAndFindable(): void
    {
        $routes = array_map(static fn(EndpointSpec $s): string => $s->route(), $this->manifest->endpoints());
        self::assertSame(count($routes), count(array_unique($routes)));
        self::assertSame('Polaris\\Http\\Auth\\LoginEndpoint', $this->manifest->find('post', '/auth/login')?->class);
        self::assertNull($this->manifest->find('GET', '/nope'));
    }

    public function testPolicyValuesAreKnown(): void
    {
        $limits = RateLimitConfig::defaults();
        foreach ($this->manifest->endpoints() as $spec) {
            self::assertContains($spec->auth, EndpointSpec::AUTH, $spec->file);
            self::assertContains($spec->effect, EndpointSpec::EFFECTS, $spec->file);
            self::assertContains($spec->inputSource, EndpointSpec::SOURCES, $spec->file);
            if ($spec->session !== null) {
                self::assertContains($spec->session, EndpointSpec::SESSIONS, $spec->file);
            }
            self::assertSame($spec->method, strtoupper($spec->method), $spec->file);
            if ($spec->rateLimit !== null) {
                $property = lcfirst((string) preg_replace_callback('/_(\w)/', static fn(array $m): string => strtoupper($m[1]), $spec->rateLimit));
                self::assertTrue(property_exists($limits, $property), "$spec->file: rate_limit $spec->rateLimit is not a RateLimitConfig group");
            }
            self::assertSame($spec->effect !== 'read', $spec->receipt, "$spec->file: receipt follows the effect unless overridden");
            if ($spec->method === 'GET') {
                self::assertSame('read', $spec->effect, "$spec->file: GET is a read");
            }
        }
    }

    public function testSchemaJsonAgreesWithTheLoader(): void
    {
        $schema = json_decode((string) file_get_contents(Loader::defaultDirectory() . '/schema.json'), true);

        self::assertIsArray($schema);
        self::assertSame(['endpoint', 'domain'], $schema['required']);
        self::assertSame(['method', 'path', 'auth', 'effect'], $schema['properties']['endpoint']['required']);
        self::assertSame(EndpointSpec::AUTH, $schema['properties']['endpoint']['properties']['auth']['enum']);
        self::assertSame(EndpointSpec::EFFECTS, $schema['properties']['endpoint']['properties']['effect']['enum']);
        self::assertSame(EndpointSpec::SOURCES, $schema['properties']['input']['properties']['source']['enum']);
        self::assertSame(EndpointSpec::SESSIONS, $schema['properties']['endpoint']['properties']['session']['enum']);
        self::assertSame(['class'], $schema['properties']['domain']['required']);
    }

    /**
     * Cookie token delivery moves a refresh token only off a route that declares `session` (docs/cookie-mode/spec.md
     * §2.2): every route of core and of every package whose success shows one declares it, but the OAuth provider's
     * token endpoint, whose refresh tokens belong to OAuth clients and stay in the body.
     */
    public function testEveryRouteThatAnswersARefreshTokenDeclaresItsSession(): void
    {
        $exceptions = ['POST /oauth2/token'];
        $packages = array_values(array_filter(glob(dirname(Loader::defaultDirectory(), 2) . '/*/api') ?: [], static fn(string $dir): bool => $dir !== dirname(Loader::defaultDirectory()) . '/api'));
        self::assertNotEmpty($packages);
        $answering = [];
        foreach ((new Loader(Loader::defaultDirectory(), ...$packages))->load()->endpoints() as $spec) {
            foreach ($spec->outputExamples as $example) {
                if ((is_array($example['data'] ?? null) && array_key_exists('refresh_token', $example['data'])) || array_key_exists('refresh_token', $example)) {
                    $answering[] = $spec->route();
                    if (!in_array($spec->route(), $exceptions, true)) {
                        self::assertContains($spec->session, ['issue', 'refresh'], "$spec->file answers a refresh token: it needs session: issue or refresh");
                    }
                }
            }
        }
        foreach ($exceptions as $route) {
            self::assertContains($route, $answering, "$route is still an exception worth listing");
        }
    }

    public function testTheOpenApiDocumentCarriesTheSessionAndTypesTheRefreshTokenOptional(): void
    {
        $paths = OpenApi::document($this->manifest)['paths'];

        $login = $paths['/auth/login']['post'];
        self::assertSame('issue', $login['x-polaris-session']);
        $variants = $login['responses']['200']['content']['application/json']['schema']['oneOf'];
        self::assertArrayHasKey('refresh_token', $variants[0]['properties']['data']['properties']);
        self::assertNotContains('refresh_token', $variants[0]['properties']['data']['required'], 'absent in cookie delivery');
        self::assertContains('access_token', $variants[0]['properties']['data']['required']);
        self::assertStringContainsString('csrf_failed | insecure_transport', $login['responses']['403']['description']);

        $refresh = $paths['/auth/token/refresh']['post'];
        self::assertSame('refresh', $refresh['x-polaris-session']);
        self::assertArrayNotHasKey('required', $refresh['requestBody']['content']['application/json']['schema'], 'the cookie can carry it');
        self::assertNotContains('refresh_token', $refresh['responses']['200']['content']['application/json']['schema']['properties']['data']['required']);

        self::assertSame('end', $paths['/auth/logout']['post']['x-polaris-session']);
        self::assertArrayNotHasKey('403', $paths['/auth/logout']['post']['responses'], 'an end route refuses nothing');
        self::assertArrayNotHasKey('x-polaris-session', $paths['/auth/me']['get']);
        self::assertSame(['email', 'password'], $paths['/auth/login']['post']['requestBody']['content']['application/json']['schema']['required'], 'only the refresh token is optional');

        // Body delivery alone (polaris/mcp's tool schemas): the token is required and nothing is refused, as in 0.11.
        $body = OpenApi::document($this->manifest, cookieDelivery: false)['paths'];
        self::assertSame(['refresh_token'], $body['/auth/token/refresh']['post']['requestBody']['content']['application/json']['schema']['required']);
        self::assertContains('refresh_token', $body['/auth/token/refresh']['post']['responses']['200']['content']['application/json']['schema']['properties']['data']['required']);
        self::assertArrayNotHasKey('403', $body['/auth/token/refresh']['post']['responses']);
    }

    public function testTheLoaderRejectsAnUnknownSession(): void
    {
        $directory = sys_get_temp_dir() . '/polaris-session-' . bin2hex(random_bytes(4));
        mkdir($directory);
        file_put_contents($directory . '/x.yaml', "endpoint: { method: POST, path: /x, auth: public, effect: write, session: open }\ndomain: { class: " . OtpFactorConfirmEndpoint::class . " }\n");
        try {
            $this->expectExceptionMessage('x.yaml: unknown session "open".');
            (new Loader($directory))->load();
        } finally {
            unlink($directory . '/x.yaml');
            rmdir($directory);
        }
    }

    public function testSpecFilesAreTheOnlyYamlUnderApi(): void
    {
        $files = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(Loader::defaultDirectory())) as $file) {
            if ($file instanceof \SplFileInfo && str_ends_with($file->getFilename(), '.yaml')) {
                $files[] = $file->getPathname();
            }
        }
        sort($files);
        self::assertCount(52, $files);
    }
}
