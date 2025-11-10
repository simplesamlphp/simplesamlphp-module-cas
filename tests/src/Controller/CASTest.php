<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\cas\Controller;

use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\CAS\XML\cas\AuthenticationSuccess;
use SimpleSAML\CAS\XML\cas\ServiceResponse;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\cas\Auth\Source\CAS;
use SimpleSAML\Module\cas\Controller;
use SimpleSAML\XML\DOMDocumentFactory;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "cas" module.
 *
 * @package SimpleSAML\Test
 */
final class CASTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    private Configuration $sourceConfig;


    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Minimal server globals needed by SimpleSAML internals
        $_SERVER['REQUEST_URI'] = '/linkback';
        $_SERVER['HTTP_HOST'] = 'localhost';
        $_SERVER['HTTPS'] = 'off';

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => [
                    'cas' => true,
                    'core' => true,
                ],
            ],
            '[ARRAY]',
            'simplesaml',
        );
        Configuration::setPreLoadedConfig($this->config, 'config.php');

        $this->sourceConfig = Configuration::getConfig('authsources.php');
        Configuration::setPreLoadedConfig($this->sourceConfig, 'authsources.php');
    }


    /**
     * Test that request without stateId results in a BadRequest-error
     */
    public function testNoStateId(): void
    {
        $request = Request::create(
            '/linkback',
            'GET',
        );

        $c = new Controller\CAS($this->config);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage("BADREQUEST('%REASON%' => 'Missing stateId parameter.')");

        $c->linkback($request);
    }


    /**
     * Test that a missing state results in a NOSTATE-error
     */
    public function testNoState(): void
    {
        $request = Request::create(
            '/linkback',
            'GET',
            ['stateId' => 'abc123'],
        );

        $c = new Controller\CAS($this->config);

        $this->expectException(Error\NoState::class);

        $c->linkback($request);
    }


    /**
     * Test that request without ticket results in a BadRequest-error
     */
    public function testNoTicket(): void
    {
        $request = Request::create(
            '/linkback',
            'GET',
            ['stateId' => 'abc123'],
        );

        $c = new Controller\CAS($this->config);
        $c->setAuthState(new class () extends Auth\State {
            /** @return array<string, mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [];
            }
        });

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage("BADREQUEST('%REASON%' => 'Missing ticket parameter.')");

        $c->linkback($request);
    }


    /**
     * Test that an unknown authsource in config throws an exception
     */
    public function testUnknownAuthSource(): void
    {
        $request = Request::create(
            '/linkback',
            'GET',
            [
                'stateId' => 'abc123',
                'ticket' => 'abc123',
            ],
        );

        $c = new Controller\CAS($this->config);
        $c->setAuthState(new class () extends Auth\State {
            /** @return array<string, mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [CAS::AUTHID => 'somethingElse'];
            }
        });

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Could not find authentication source with id somethingElse');
        $result = $c->linkback($request);
    }


    /**
     * Test that request without all parameters set results in a RunnableResponse
     */
    public function testNormalOperation(): void
    {
        $request = Request::create(
            '/linkback',
            'GET',
            [
                'stateId' => 'abc123',
                'ticket' => 'abc123',
            ],
        );

        $c = new Controller\CAS($this->config);
        $c->setAuthState(new class () extends Auth\State {
            /** @return array<string, mixed> */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): array
            {
                return [CAS::AUTHID => 'something'];
            }
        });
        $c->setAuthSource(new class () extends Auth\Source {
            public function __construct()
            {
                //dummy
            }


            /**
             * @param array<mixed> $state
             */
            public function authenticate(array &$state): void
            {
                //dummy
            }


            public static function getById(string $authId, ?string $type = null): Auth\Source
            {
                return new class () extends CAS {
                    public function __construct()
                    {
                        //dummy
                    }


                    /** @param array<mixed> $state */
                    public function finalStep(array &$state): void
                    {
                        //dummy
                    }
                };
            }
        });

        $result = $c->linkback($request);
        $this->assertInstanceOf(RunnableResponse::class, $result);
    }

    /**
     * Provide both CAS configs: relative (casserver) and absolute (casserver_legacy).
     *
     * @return array<array{0: string}>
     */
    public static function casConfigsProvider(): array
    {
        return [
            "casserver short attribute mapping" => ['casserver'],
            "casserver legacy/long attribute mapping" => ['casserver_legacy'],
        ];
    }

    /**
     * Run the same extraction assertions for both configurations.
     *
     * @param string $sourceKey The key of the CAS configuration to test ('casserver' or 'casserver_legacy')
     * @throws \ReflectionException
     */
    #[DataProvider('casConfigsProvider')]
    public function testCasConfigAbsoluteXPathsReturnValues(string $sourceKey): void
    {
        $authsources = Configuration::getConfig('authsources.php');
        $config = $authsources->toArray();

        self::assertIsArray($config, 'authsources.php did not return expected $config array');
        self::assertArrayHasKey($sourceKey, $config, "Missing source '$sourceKey' in authsources.php");
        $sourceConfig = $config[$sourceKey];
        self::assertArrayHasKey('cas', $sourceConfig, "Missing 'cas' config for '$sourceKey'");
        self::assertArrayHasKey('ldap', $sourceConfig, "Missing 'ldap' config for '$sourceKey'");

        // Load the CAS success message XML and build an AuthenticationSuccess message
        $successXmlFile = dirname(__DIR__, 1) . '/../response/cas-success-service-response.xml';
        self::assertFileExists($successXmlFile, 'CAS success XML not found at expected path');

        $dom = DOMDocumentFactory::fromFile($successXmlFile);
        // Ensure documentElement is a DOMElement before passing to fromXML()
        $root = $dom->documentElement;
        if (!$root instanceof \DOMElement) {
            self::fail('Loaded XML does not have a document element');
        }
        $serviceResponse = ServiceResponse::fromXML($root);
        $message = $serviceResponse->getResponse();
        self::assertInstanceOf(
            AuthenticationSuccess::class,
            $message,
            'Expected AuthenticationSuccess message',
        );

        // Instantiate the CAS source with the selected configuration
        $cas = new Cas(['AuthId' => 'unit-cas'], $sourceConfig);

        // Invoke the private parseUserAndAttributes() method via reflection
        $refMethod = new \ReflectionMethod(Cas::class, 'parseUserAndAttributes');
        $refMethod->setAccessible(true);
        /** @var array{0:string,1:array<string,array<int,string>>} $result */
        $result = $refMethod->invoke($cas, $message);

        // Assert user and attributes are identical for both configurations
        [$user, $attributes] = $result;

        self::assertSame('jdoe', $user, "$sourceKey: user mismatch");
        self::assertSame(['jdoe'], $attributes['uid'] ?? [], "$sourceKey: uid not extracted");
        self::assertSame(['Doe'], $attributes['sn'] ?? [], "$sourceKey: sn not extracted");
        self::assertSame(['John'], $attributes['givenName'] ?? [], "$sourceKey: givenName not extracted");
        self::assertSame(['jdoe@example.edu'], $attributes['mail'] ?? [], "$sourceKey: mail not extracted");
        self::assertSame(
            ['jdoe@example.edu'],
            $attributes['eduPersonPrincipalName'] ?? [],
            "$sourceKey: ePPN not extracted",
        );
    }
}
