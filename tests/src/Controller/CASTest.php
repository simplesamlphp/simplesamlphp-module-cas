<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\cas\Controller;

use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\cas\Auth\Source\CAS;
use SimpleSAML\Module\cas\Controller;
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

        $this->sourceConfig = Configuration::loadFromArray([
            'something' => [
                'cas:CAS',
                'cas' => [
                    'login' => 'https://example.org/login',
                    'validate' => 'https://example.org/validate',
                ],
                'ldap' => [],
            ],
        ]);
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
            /** @return array<mixed>|null */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
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
            /** @return array<mixed>|null */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
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
            /** @return array<mixed>|null */
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
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


            public static function getById(string $authId, ?string $type = null): ?Auth\Source
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
}
