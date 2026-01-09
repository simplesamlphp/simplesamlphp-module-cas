<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\cas\Controller;

use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\CAS\XML\AuthenticationSuccess;
use SimpleSAML\CAS\XML\ServiceResponse;
use SimpleSAML\CAS\XML\ServiceResponse as CasServiceResponse;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\cas\Auth\Source\CAS;
use SimpleSAML\Module\cas\Controller;
use SimpleSAML\Slate\XML\AuthenticationSuccess as SlateAuthenticationSuccess;
use SimpleSAML\Slate\XML\ServiceResponse as SlateServiceResponse;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSchema\Type\Interface\ValueTypeInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

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
                    'ldap' => true,
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
     * Verify constructor picks serviceValidate and login from the 'casserver' config
     * (serviceValidate preferred when present).
     *
     * @throws \ReflectionException
     */
    public function testConstructorUsesServiceValidateWhenPresent(): void
    {
        $authsources = Configuration::getConfig('authsources.php')->toArray();
        self::assertArrayHasKey('casserver', $authsources);
        $sourceConfig = $authsources['casserver'];

        $cas = new CAS(['AuthId' => 'unit-cas'], $sourceConfig);

        $ref = new \ReflectionClass($cas);
        $validationMethod = $ref->getProperty('validationMethod');
        $validationMethod->setAccessible(true);
        $loginMethod = $ref->getProperty('loginMethod');
        $loginMethod->setAccessible(true);

        self::assertSame('serviceValidate', $validationMethod->getValue($cas));
        self::assertSame(
            'https://ugrad.apply.example.edu/account/cas/login',
            $loginMethod->getValue($cas),
        );
    }


    /**
     * Verify constructor falls back to validate when serviceValidate is absent
     * using the 'something' authsource.
     *
     * @throws \ReflectionException
     */
    public function testConstructorUsesValidateWhenServiceValidateMissing(): void
    {
        $authsources = Configuration::getConfig('authsources.php')->toArray();
        self::assertArrayHasKey('something', $authsources);
        $sourceConfig = $authsources['something'];

        $cas = new CAS(['AuthId' => 'unit-cas'], $sourceConfig);

        $ref = new \ReflectionClass($cas);
        $validationMethod = $ref->getProperty('validationMethod');
        $validationMethod->setAccessible(true);
        $loginMethod = $ref->getProperty('loginMethod');
        $loginMethod->setAccessible(true);

        self::assertSame('validate', $validationMethod->getValue($cas));
        self::assertSame('https://example.org/login', $loginMethod->getValue($cas));
    }


    /**
     * When both serviceValidate and validate are present, serviceValidate is preferred.
     *
     * @throws \ReflectionException
     */
    public function testConstructorPrefersServiceValidateIfBothPresent(): void
    {
        $config = [
            'cas' => [
                'login' => 'https://example.org/login',
                'serviceValidate' => 'https://example.org/sv',
                'validate' => 'https://example.org/v',
            ],
            'ldap' => [],
        ];

        $cas = new CAS(['AuthId' => 'unit-cas'], $config);

        $ref = new \ReflectionClass($cas);
        $validationMethod = $ref->getProperty('validationMethod');
        $validationMethod->setAccessible(true);

        self::assertSame('serviceValidate', $validationMethod->getValue($cas));
    }


    /**
     * Missing both serviceValidate and validate should throw.
     */
    public function testConstructorThrowsIfNoValidationMethodConfigured(): void
    {
        $config = [
            'cas' => [
                'login' => 'https://example.org/login',
                // no serviceValidate / validate
            ],
            'ldap' => [],
        ];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('validate or serviceValidate not specified');
        new CAS(['AuthId' => 'unit-cas'], $config);
    }


    /**
     * Missing login should throw.
     */
    public function testConstructorThrowsIfNoLoginConfigured(): void
    {
        $config = [
            'cas' => [
                'serviceValidate' => 'https://example.org/sv',
                // no login
            ],
            'ldap' => [],
        ];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('cas login URL not specified');
        new CAS(['AuthId' => 'unit-cas'], $config);
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
        $errorResponse = [
            'errorCode' => 'BADREQUEST',
            '%REASON%' => 'Missing stateId parameter.',
        ];
        $this->expectExceptionMessage(json_encode($errorResponse, JSON_THROW_ON_ERROR));
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
        $errorResponse = [
            'errorCode' => 'BADREQUEST',
            '%REASON%' => 'Missing ticket parameter.',
        ];
        $this->expectExceptionMessage(json_encode($errorResponse, JSON_THROW_ON_ERROR));

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
        /*
         * @var mixed $result
         * @phpstan-ignore method.alreadyNarrowedType
         */
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

        self::assertArrayHasKey($sourceKey, $config, "Missing source '$sourceKey' in authsources.php");
        $sourceConfig = $config[$sourceKey];
        /** @var array<mixed> $sourceConfig */
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
            \SimpleSAML\CAS\XML\AuthenticationSuccess::class,
            $message,
            'Expected AuthenticationSuccess message',
        );

        // Instantiate the CAS source with the selected configuration
        $cas = new Cas(['AuthId' => 'unit-cas'], $sourceConfig);

        // Invoke the new private methods via reflection
        $ref = new \ReflectionClass(Cas::class);

        $parseAuthSuccess = $ref->getMethod('parseAuthenticationSuccess');
        $parseAuthSuccess->setAccessible(true);
        /** @var array{0:string,1:array<string,list<string>>} $userAndAttrs */
        $userAndAttrs = $parseAuthSuccess->invoke($cas, $message);

        $parseQueryAttrs = $ref->getMethod('parseQueryAttributes');
        $parseQueryAttrs->setAccessible(true);
        /** @var array<string,list<string>> $queryAttrs */
        $queryAttrs = $parseQueryAttrs->invoke($cas, $dom);

        // Merge attribute arrays (values are lists)
        [$user, $elementAttrs] = $userAndAttrs;
        // Normalize user to a plain string (may be a StringValue-like object)
        $user = strval($user);

        /** @var array<string,list<string>> $attributes */
        $attributes = $elementAttrs;
        foreach ($queryAttrs as $k => $vals) {
            if (!isset($attributes[$k])) {
                $attributes[$k] = [];
            }
            // Append preserving order
            foreach ($vals as $v) {
                $attributes[$k][] = $v;
            }
        }

        // Assert user and attributes are identical for both configurations
        self::assertSame('jdoe', $user, "$sourceKey: user mismatch");
        //phpcs:ignore Generic.Files.LineLength.TooLong
        self::assertSame('12345', array_pop($attributes['person']) ?? '', "$sourceKey: person not extracted");
        //phpcs:ignore Generic.Files.LineLength.TooLong
        self::assertSame('12345_top', array_pop($attributes['person_top']) ?? '', "$sourceKey: person top not extracted");
        //phpcs:ignore Generic.Files.LineLength.TooLong
        self::assertSame('Doe', array_pop($attributes['sn']) ?? '', "$sourceKey: sn not extracted");
        //phpcs:ignore Generic.Files.LineLength.TooLong
        self::assertSame('John', array_pop($attributes['givenName']) ?? '', "$sourceKey: givenName not extracted");
        //phpcs:ignore Generic.Files.LineLength.TooLong
        self::assertSame('jdoe@example.edu', array_pop($attributes['mail']) ?? '', "$sourceKey: mail not extracted");
        //phpcs:ignore Generic.Files.LineLength.TooLong
        self::assertSame('jdoe@example.edu', array_pop($attributes['eduPersonPrincipalName']) ?? '', "$sourceKey: ePPN not extracted",);
    }


    /**
     * Ensure that for casserver attributes configuration and the slate CAS response,
     * the attributes built from the AuthenticationSuccess model match
     * exactly those extracted via XPath configuration: same keys,
     * same values (per key), and same total count.
     */
    public function testCasserverAutoMapAttributesMatchBetweenModelAndXPath(): void
    {
        // Load authsources and retrieve casserver_auto_map configuration
        $authsources = Configuration::getConfig('authsources.php');
        $config = $authsources->toArray();

        self::assertArrayHasKey(
            'casserver_auto_map',
            $config,
            "Missing source 'casserver_auto_map' in authsources.php",
        );
        $sourceConfig = $config['casserver_auto_map'];
        /** @var array<mixed> $sourceConfig */

        self::assertArrayHasKey('cas', $sourceConfig, "Missing 'cas' config for 'casserver_auto_map'");
        self::assertArrayHasKey('ldap', $sourceConfig, "Missing 'ldap' config for 'casserver_auto_map'");

        // Load the CAS success message XML (slate variant)
        $successXmlFile = dirname(__DIR__, 1) . '/../response/cas-success-service-response-slate.xml';
        self::assertFileExists($successXmlFile, 'Slate CAS success XML not found at expected path');

        $dom = DOMDocumentFactory::fromFile($successXmlFile);
        $root = $dom->documentElement;
        if (!$root instanceof \DOMElement) {
            self::fail('Loaded slate XML does not have a document element');
        }

        $isSlateEnabled = $sourceConfig['cas']['slate.enabled'] ?? false;
        // Build AuthenticationSuccess message from XML.
        // With xml-cas-module-slate installed, this will be a SlateAuthenticationSuccess instance.
        $serviceResponse = $isSlateEnabled ? SlateServiceResponse::fromXML($root) : CasServiceResponse::fromXML($root);

        $message = $serviceResponse->getResponse();
        self::assertInstanceOf(
            $isSlateEnabled ? SlateAuthenticationSuccess::class : AuthenticationSuccess::class,
            $message,
            'Expected SlateAuthenticationSuccess message for slate XML',
        );

        // Instantiate the CAS source with casserver_auto_map configuration
        $cas = new CAS(['AuthId' => 'unit-cas'], $sourceConfig);

        // Use reflection to access the private parsers
        $ref = new \ReflectionClass(CAS::class);

        $parseAuthSuccess = $ref->getMethod('parseAuthenticationSuccess');
        $parseAuthSuccess->setAccessible(true);
        /** @var array{0:mixed,1:array<string,list<string>>} $userAndModelAttrs */
        $userAndModelAttrs = $parseAuthSuccess->invoke($cas, $message);

        $parseQueryAttrs = $ref->getMethod('parseQueryAttributes');
        $parseQueryAttrs->setAccessible(true);
        /** @var array<string,list<string>> $xpathAttrs */
        $xpathAttrs = $parseQueryAttrs->invoke($cas, $dom);

        [$user, $modelAttrs] = $userAndModelAttrs;

        self::assertInstanceOf(ValueTypeInterface::class, $user);
        $modelAttrs['user'] = [$user->getValue()];

        // Assert same keys
        $modelKeys = array_keys($modelAttrs);
        $xpathKeys = array_keys($xpathAttrs);
        sort($modelKeys);
        sort($xpathKeys);

        self::assertSame($modelKeys, $xpathKeys, 'Attribute keys mismatch between model and XPath extraction');

        foreach ($modelAttrs as $key => $values) {
            $this->assertTrue(isset($xpathAttrs[$key]), "Missing attribute '$key' in XPath extraction");
            $this->assertTrue(
                in_array($values[0], $xpathAttrs[$key], true),
                "Attribute '$key' values mismatch",
            );
        }
    }


    /**
     * finalStep() should throw if ldap.authsource points to a non‑existent authsource.
     */
    public function testFinalStepThrowsWhenLdapAuthsourceNotFound(): void
    {
        $config = [
            'cas' => [
                'login'          => 'https://example.org/login',
                'serviceValidate' => 'https://example.org/serviceValidate',
                'logout'         => 'https://example.org/logout',
            ],
            'ldap' => [
                'authsource' => 'missing-backend',
            ],
        ];

        // Override casValidation to avoid real HTTP calls
        $cas = new class (['AuthId' => 'unit-cas'], $config) extends CAS {
            protected function casValidation(string $ticket, string $service): array
            {
                return ['user123', ['fromCas' => ['value']]];
            }
        };

        $state = ['cas:ticket' => 'ST-1-abc'];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Could not find authentication source with id missing-backend');

        $cas->finalStep($state);
    }


    /**
     * finalStep() should throw if ldap.authsource exists but is not an LDAP authsource.
     *
     * Here we re‑use the "something" authsource from the tests' authsources.php,
     * which is configured as a cas:CAS authsource, not ldap:LDAP.
     */
    public function testFinalStepThrowsWhenLdapAuthsourceIsNotLdap(): void
    {
        $config = [
            'cas' => [
                'login'          => 'https://example.org/login',
                'serviceValidate' => 'https://example.org/serviceValidate',
                'logout'         => 'https://example.org/logout',
            ],
            'ldap' => [
                'authsource' => 'something',
            ],
        ];

        $cas = new class (['AuthId' => 'unit-cas'], $config) extends CAS {
            protected function casValidation(string $ticket, string $service): array
            {
                return ['user123', ['fromCas' => ['value']]];
            }
        };

        $state = ['cas:ticket' => 'ST-1-abc'];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage(
            "Configured ldap.authsource 'something' is not an LDAP authsource.",
        );

        $cas->finalStep($state);
    }


    /**
     * Test that CAS finalStep() handles LDAP errors gracefully.
     * When LDAP lookup fails, the method should:
     * - Not throw an exception
     * - Only use attributes from CAS validation
     * - Set the username from CAS in the state
     */
    public function testFinalStepSwallowsLdapErrorException(): void
    {
        $config = [
            'cas' => [
                'login'   => 'https://example.org/login',
                'validate' => 'https://example.org/validate',   // CAS 1.0, no serviceValidate
                // no 'serviceValidate' here on purpose
                'logout'  => 'https://example.org/logout',
            ],
            'ldap' => [
                'authsource' => 'ldap-backend',
            ],
        ];

        $cas = new CAS(['AuthId' => 'unit-cas'], $config);

        // Mock HttpClient: casValidate() expects "yes\n<user>\n"
        $httpClient = $this->createMock(HttpClientInterface::class);
        $response   = $this->createMock(ResponseInterface::class);

        $httpClient
            ->method('request')
            ->willReturn($response);

        $response
            ->method('getContent')
            ->willReturn("yes\nuser123\n");

        // Inject mocked client
        $ref = new \ReflectionClass($cas);
        $initHttpClient = $ref->getMethod('initHttpClient');
        $initHttpClient->setAccessible(true);
        $initHttpClient->invoke($cas, $httpClient);

        $state = ['cas:ticket' => 'ST-1-xyz'];

        // Should not throw; LDAP error will be caught
        $cas->finalStep($state);

        // Attributes should come from CAS only; LDAP failure resulted in $ldapAttributes = []
        $this->assertArrayHasKey('Attributes', $state);
        $this->assertSame([], $state['Attributes']);
    }
}
