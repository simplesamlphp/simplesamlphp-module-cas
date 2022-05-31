<?php

declare(strict_types=1);

namespace SimpleSAML\Module\cas\Controller;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\cas\Auth\Source\CAS as CASSource;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the cas module.
 *
 * This class serves the different views available in the module.
 *
 * @package simplesamlphp/simplesamlphp-module-cas
 */
class CAS
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;

    /**
     * @var \SimpleSAML\Auth\Source|string
     * @psalm-var \SimpleSAML\Auth\Source|class-string
     */
    protected $authSource = Auth\Source::class;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config
    ) {
        $this->config = $config;
    }


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }


    /**
     * Inject the \SimpleSAML\Auth\Source dependency.
     *
     * @param \SimpleSAML\Auth\Source $authSource
     */
    public function setAuthSource(Auth\Source $authSource): void
    {
        $this->authSource = $authSource;
    }


    /**
     * Handle linkback-response from CAS.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function linkback(Request $request): RunnableResponse
    {
        if (!$request->query->has('StateId')) {
            throw new Error\BadRequest('Missing StateId parameter.');
        }

        $stateId = $request->query->get('StateId');
        $state = $this->authState::loadState($stateId, CASSource::STAGE_INIT);

        if (!$request->query->has('ticket')) {
            throw new Error\BadRequest('Missing ticket parameter.');
        }

        $ticket = $request->query->get('ticket');
        $state['cas:ticket'] = $ticket;

        // Find authentication source
        Assert::keyExists($state, CASSource::AUTHID);
        $sourceId = $state[CASSource::AUTHID];

        /** @var \SimpleSAML\Module\cas\Auth\Source\CAS|null $source */
        $source = $this->authSource::getById($sourceId);
        if ($source === null) {
            throw new Exception('Could not find authentication source with id ' . $sourceId);
        }

        $source->finalStep($state);
        return new RunnableResponse([Auth\Source::class, 'completeAuth'], [&$state]);
    }
}
