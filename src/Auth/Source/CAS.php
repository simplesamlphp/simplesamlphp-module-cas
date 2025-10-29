<?php

declare(strict_types=1);

namespace SimpleSAML\Module\cas\Auth\Source;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\CAS\Utils\XPath;
use SimpleSAML\CAS\XML\cas\AuthenticationFailure;
use SimpleSAML\CAS\XML\cas\AuthenticationSuccess;
use SimpleSAML\CAS\XML\cas\ServiceResponse;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\Module\ldap\Auth\Ldap;
use SimpleSAML\Utils;
use SimpleSAML\XML\DOMDocumentFactory;

use function array_key_exists;
use function array_merge_recursive;
use function preg_split;
use function strcmp;
use function strval;
use function var_export;

/**
 * Authenticate using CAS.
 *
 * Based on www/auth/login-cas.php by Mads Freek, RUC.
 *
 * @package SimpleSAMLphp
 */

class CAS extends Auth\Source
{
    /**
     * The string used to identify our states.
     */
    public const STAGE_INIT = '\SimpleSAML\Module\cas\Auth\Source\CAS.state';

    /**
     * The key of the AuthId field in the state.
     */
    public const AUTHID = '\SimpleSAML\Module\cas\Auth\Source\CAS.AuthId';


    /**
     * @var array<mixed> with ldap configuration
     */
    private array $ldapConfig;

    /**
     * @var array<mixed> cas configuration
     */
    private array $casConfig;

    /**
     * @var string cas chosen validation method
     */

    private string $validationMethod;

    /**
     * @var string cas login method
     */
    private string $loginMethod;


    /**
     * Constructor for this authentication source.
     *
     * @param array<mixed> $info  Information about this authentication source.
     * @param array<mixed> $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (!array_key_exists('cas', $config)) {
            throw new Exception('cas authentication source is not properly configured: missing [cas]');
        }

        if (!array_key_exists('ldap', $config)) {
            throw new Exception('ldap authentication source is not properly configured: missing [ldap]');
        }

        $this->casConfig = $config['cas'];
        $this->ldapConfig = $config['ldap'];

        if (isset($this->casConfig['serviceValidate'])) {
            $this->validationMethod = 'serviceValidate';
        } elseif (isset($this->casConfig['validate'])) {
            $this->validationMethod = 'validate';
        } else {
            throw new Exception("validate or serviceValidate not specified");
        }

        if (isset($this->casConfig['login'])) {
            $this->loginMethod = $this->casConfig['login'];
        } else {
            throw new Exception("cas login URL not specified");
        }
    }


    /**
     * This the most simple version of validating, this provides only authentication validation
     *
     * @param string $ticket
     * @param string $service
     *
     * @return array<mixed> username and attributes
     */
    private function casValidate(string $ticket, string $service): array
    {
        $httpUtils = new Utils\HTTP();
        $url = $httpUtils->addURLParameters($this->casConfig['validate'], [
            'ticket' => $ticket,
            'service' => $service,
        ]);

        /** @var string $result */
        $result = $httpUtils->fetch($url);

        /** @var string $res */
        $res = preg_split("/\r?\n/", $result);

        if (strcmp($res[0], "yes") == 0) {
            return [$res[1], []];
        } else {
            throw new Exception("Failed to validate CAS service ticket: $ticket");
        }
    }


    /**
     * Uses the cas service validate, this provides additional attributes
     *
     * @param string $ticket
     * @param string $service
     *
     * @return array<mixed> username and attributes
     */
    private function casServiceValidate(string $ticket, string $service): array
    {
        $httpUtils = new Utils\HTTP();
        $url = $httpUtils->addURLParameters(
            $this->casConfig['serviceValidate'],
            [
                'ticket' => $ticket,
                'service' => $service,
            ],
        );
        $result = $httpUtils->fetch($url);

        /** @var string $result */
        $dom = DOMDocumentFactory::fromString($result);

        $serviceResponse = ServiceResponse::fromXML($dom->documentElement);
        $message = $serviceResponse->getResponse();
        if ($message instanceof AuthenticationFailure) {
            throw new Exception(sprintf(
                "Error when validating CAS service ticket: %s (%s)",
                strval($message->getContent()),
                strval($message->getCode()),
            ));
        } elseif ($message instanceof AuthenticationSuccess) {
            $user = $message->getUser()->getContent();
            $xPath = XPath::getXPath($message->toXML());

            $attributes = [];
            if ($casattributes = $this->casConfig['attributes']) {
                // Some have attributes in the xml - attributes is a list of XPath expressions to get them
                foreach ($casattributes as $name => $query) {
                    $attrs = XPath::xpQuery($message->toXML(), $query, $xPath);
                    foreach ($attrs as $attrvalue) {
                        $attributes[$name][] = $attrvalue->textContent;
                    }
                }
            }

            return [$user, $attributes];
        }

        throw new Exception("Error parsing serviceResponse.");
    }


    /**
     * Main validation method, redirects to correct method
     * (keeps finalStep clean)
     *
     * @param string $ticket
     * @param string $service
     * @return array<mixed> username and attributes
     */
    protected function casValidation(string $ticket, string $service): array
    {
        switch ($this->validationMethod) {
            case 'validate':
                return  $this->casValidate($ticket, $service);
            case 'serviceValidate':
                return $this->casServiceValidate($ticket, $service);
            default:
                throw new Exception("validate or serviceValidate not specified");
        }
    }


    /**
     * Called by linkback, to finish validate/ finish logging in.
     * @param array<mixed> $state
     */
    public function finalStep(array &$state): void
    {
        $ticket = $state['cas:ticket'];
        $stateId = Auth\State::saveState($state, self::STAGE_INIT);
        $service = Module::getModuleURL('cas/linkback.php', ['stateId' => $stateId]);
        list($username, $casAttributes) = $this->casValidation($ticket, $service);
        $ldapAttributes = [];

        $config = Configuration::loadFromArray(
            $this->ldapConfig,
            'Authentication source ' . var_export($this->authId, true),
        );
        if (!empty($this->ldapConfig['servers'])) {
            $ldap = new Ldap(
                $config->getString('servers'),
                $config->getOptionalBoolean('enable_tls', false),
                $config->getOptionalBoolean('debug', false),
                $config->getOptionalInteger('timeout', 0),
                $config->getOptionalInteger('port', 389),
                $config->getOptionalBoolean('referrals', true),
            );

            $ldapAttributes = $ldap->validate($this->ldapConfig, $username);
            if ($ldapAttributes === false) {
                throw new Exception("Failed to authenticate against LDAP-server.");
            }
        }
        $attributes = array_merge_recursive($casAttributes, $ldapAttributes);
        $state['Attributes'] = $attributes;
    }


    /**
     * Log-in using cas
     *
     * @param array<mixed> &$state  Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        // We are going to need the authId in order to retrieve this authentication source later
        $state[self::AUTHID] = $this->authId;

        $stateId = Auth\State::saveState($state, self::STAGE_INIT);

        $serviceUrl = Module::getModuleURL('cas/linkback.php', ['stateId' => $stateId]);

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($this->loginMethod, ['service' => $serviceUrl]);
    }


    /**
     * Log out from this authentication source.
     *
     * This function should be overridden if the authentication source requires special
     * steps to complete a logout operation.
     *
     * If the logout process requires a redirect, the state should be saved. Once the
     * logout operation is completed, the state should be restored, and completeLogout
     * should be called with the state. If this operation can be completed without
     * showing the user a page, or redirecting, this function should return.
     *
     * @param array<mixed> &$state  Information about the current logout operation.
     */
    public function logout(array &$state): void
    {
        $logoutUrl = $this->casConfig['logout'];

        Auth\State::deleteState($state);

        // we want cas to log us out
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($logoutUrl);
    }
}
