<?php

namespace SimpleSAML\Module\cas\Auth\Source;

use DOMXpath;
use Exception;
use SAML2\DOMDocumentFactory;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\Module\ldap\Auth\Ldap;
use SimpleSAML\Utils;

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
     * @var array with ldap configuration
     */
    private array $ldapConfig;

    /**
     * @var array cas configuration
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
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
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
     * @return array username and attributes
     */
    private function casValidate(string $ticket, string $service): array
    {
        $httpUtils = new Utils\HTTP();
        $url = $httpUtils->addURLParameters($this->casConfig['validate'], [
            'ticket' => $ticket,
            'service' => $service,
        ]);
        $result = $httpUtils->fetch($url);

        /** @var string $result */
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
     * @return array username and attributes
     */
    private function casServiceValidate(string $ticket, string $service): array
    {
        $httpUtils = new Utils\HTTP();
        $url = $httpUtils->addURLParameters(
            $this->casConfig['serviceValidate'],
            [
                'ticket' => $ticket,
                'service' => $service,
            ]
        );
        $result = $httpUtils->fetch($url);

        /** @var string $result */
        $dom = DOMDocumentFactory::fromString($result);
        $xPath = new DOMXpath($dom);
        $xPath->registerNamespace("cas", 'http://www.yale.edu/tp/cas');
        $success = $xPath->query("/cas:serviceResponse/cas:authenticationSuccess/cas:user");
        if ($success->length == 0) {
            $failure = $xPath->evaluate("/cas:serviceResponse/cas:authenticationFailure");
            throw new Exception("Error when validating CAS service ticket: " . $failure->item(0)->textContent);
        } else {
            $attributes = [];
            if ($casattributes = $this->casConfig['attributes']) {
                // Some has attributes in the xml - attributes is a list of XPath expressions to get them
                foreach ($casattributes as $name => $query) {
                    $attrs = $xPath->query($query);
                    foreach ($attrs as $attrvalue) {
                        $attributes[$name][] = $attrvalue->textContent;
                    }
                }
            }

            $item = $success->item(0);
            if (is_null($item)) {
                throw new Exception("Error parsing serviceResponse.");
            }
            $casusername = $item->textContent;

            return [$casusername, $attributes];
        }
    }


    /**
     * Main validation method, redirects to correct method
     * (keeps finalStep clean)
     *
     * @param string $ticket
     * @param string $service
     * @return array username and attributes
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
     * @param array $state
     */
    public function finalStep(array &$state): void
    {
        $ticket = $state['cas:ticket'];
        $stateID = Auth\State::saveState($state, self::STAGE_INIT);
        $service = Module::getModuleURL('cas/linkback.php', ['stateID' => $stateID]);
        list($username, $casattributes) = $this->casValidation($ticket, $service);
        $ldapattributes = [];

        $config = Configuration::loadFromArray(
            $this->ldapConfig,
            'Authentication source ' . var_export($this->authId, true)
        );
        if ($this->ldapConfig['servers']) {
            $ldap = new Ldap(
                $config->getString('servers'),
                $config->getOptionalBoolean('enable_tls', false),
                $config->getOptionalBoolean('debug', false),
                $config->getOptionalInteger('timeout', 0),
                $config->getOptionalInteger('port', 389),
                $config->getOptionalBoolean('referrals', true)
            );
            $ldapattributes = $ldap->validate($this->ldapConfig, $username);
            if ($ldapattributes === false) {
                throw new Exception("Failed to authenticate against LDAP-server.");
            }
        }
        $attributes = array_merge_recursive($casattributes, $ldapattributes);
        $state['Attributes'] = $attributes;

        Auth\Source::completeAuth($state);
    }


    /**
     * Log-in using cas
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        // We are going to need the authId in order to retrieve this authentication source later
        $state[self::AUTHID] = $this->authId;

        $stateID = Auth\State::saveState($state, self::STAGE_INIT);

        $serviceUrl = Module::getModuleURL('cas/linkback.php', ['stateID' => $stateID]);

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
     * @param array &$state  Information about the current logout operation.
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
