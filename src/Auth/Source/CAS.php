<?php

declare(strict_types=1);

namespace SimpleSAML\Module\cas\Auth\Source;

use DOMDocument;
use DOMElement;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\CAS\Utils\XPath;
use SimpleSAML\CAS\XML\AuthenticationFailure;
use SimpleSAML\CAS\XML\AuthenticationSuccess as CasAuthnSuccess;
use SimpleSAML\CAS\XML\ServiceResponse as CasServiceResponse;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\ldap\Auth\Ldap;
use SimpleSAML\Slate\XML\AuthenticationSuccess as SlateAuthnSuccess;
use SimpleSAML\Slate\XML\ServiceResponse as SlateServiceResponse;
use SimpleSAML\Utils;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

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
    public const string STAGE_INIT = '\SimpleSAML\Module\cas\Auth\Source\CAS.state';

    /**
     * The key of the AuthId field in the state.
     */
    public const string AUTHID = '\SimpleSAML\Module\cas\Auth\Source\CAS.AuthId';


    /**
     * @var array<string, mixed> with ldap configuration
     */
    private array $ldapConfig;

    /**
     * @var array<string, mixed> cas configuration
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
     * @var bool flag indicating if slate XML format should be used
     */
    private bool $useSlate;

    /**
     * HTTP utilities instance for handling redirects and URLs.
     */
    private Utils\HTTP $httpUtils;

    /**
     * Symfony HTTP client for CAS requests.
     */
    private HttpClientInterface $httpClient;


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

        $authsources = Configuration::loadFromArray($config);

        $this->casConfig = (array)$authsources->getValue('cas');
        $this->ldapConfig = (array)$authsources->getValue('ldap');

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

        $this->useSlate = $this->casConfig['slate.enabled'] ?? false;
    }


    /**
     * Initialize HttpClient instance
     *
     * @param \Symfony\Contracts\HttpClient\HttpClientInterface|null $httpClient Optional HTTP client instance to use
     */
    protected function initHttpClient(?HttpClientInterface $httpClient = null): void
    {
        if ($httpClient !== null) {
            $this->httpClient = $httpClient;
        } else {
            $this->httpClient = $this->httpClient ?? HttpClient::create();
        }
    }


    /**
     * Initialize HTTP utilities instance
     *
     * @param \SimpleSAML\Utils\HTTP|null $httpUtils Optional HTTP utilities instance to use
     * @return void
     * @deprecated This helper is kept only for the legacy authenticate(array &$state): void
     *             flow. Once the Request-based authenticate(Request, array &$state): ?Response
     *             API is active in SimpleSAMLphp, this method will be removed and HTTP
     *             handling should be done via Symfony responses instead.
     */
    protected function initHttpUtils(?Utils\HTTP $httpUtils = null): void
    {
        if ($httpUtils !== null) {
            $this->httpUtils = $httpUtils;
        } else {
            $this->httpUtils = $this->httpUtils ?? new Utils\HTTP();
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
        $this->initHttpClient();

        $response = $this->httpClient->request('GET', $this->casConfig['validate'], [
            'query' => [
                'ticket'  => $ticket,
                'service' => $service,
            ],
        ]);

        $result = $response->getContent();

        /** @var list<string> $res */
        $res = preg_split("/\r?\n/", $result) ?: [];

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
        $this->initHttpClient();

        $response = $this->httpClient->request('GET', $this->casConfig['serviceValidate'], [
            'query' => [
                'ticket'  => $ticket,
                'service' => $service,
            ],
        ]);

        $result = $response->getContent();

        /** @var string $result */
        $dom = DOMDocumentFactory::fromString($result);

        // In practice that `if (...) return [];` branch is unreachable with the current behavior.
        // `DOMDocumentFactory::fromString()`
        // PHPStan still flags / cares about it because it only sees
        // and has no way to know `null` won’t actually occur here. `DOMElement|null`
        if ($dom->documentElement === null) {
            return [];
        }

        if ($this->useSlate) {
            $serviceResponse = SlateServiceResponse::fromXML($dom->documentElement);
        } else {
            $serviceResponse = CasServiceResponse::fromXML($dom->documentElement);
        }

        $message = $serviceResponse->getResponse();
        if ($message instanceof AuthenticationFailure) {
            throw new Exception(sprintf(
                "Error when validating CAS service ticket: %s (%s)",
                strval($message->getContent()),
                strval($message->getCode()),
            ));
        } elseif ($message instanceof CasAuthnSuccess || $message instanceof SlateAuthnSuccess) {
            [$user, $attributes] = $this->parseAuthenticationSuccess($message);

            // This will only be parsed if i have an attribute query. If the configuration
            // array is empty or not set then an empty array will be returned.
            $attributesFromQueryConfiguration = $this->parseQueryAttributes($dom);
            if (!empty($attributesFromQueryConfiguration)) {
              // Overwrite attributes from parseAuthenticationSuccess with configured
              // XPath-based attributes, instead of combining them.
                foreach ($attributesFromQueryConfiguration as $name => $values) {
                  // Ensure a clean, unique list of string values
                    $values = array_values(array_unique(array_map('strval', $values)));

                  // Configuration wins: replace any existing attribute with the same name
                    $attributes[$name] = $values;
                }
            }

            return [$user, $attributes];
        }

        throw new Exception("Error parsing serviceResponse.");
    }


    /**
     * Main validation method, redirects to the correct method
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

        $this->initHttpUtils();
        $this->httpUtils->redirectTrustedURL($this->loginMethod, ['service' => $serviceUrl]);
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
        $this->initHttpUtils();
        $this->httpUtils->redirectTrustedURL($logoutUrl);
    }


    /**
     * Parse a CAS AuthenticationSuccess into a flat associative array.
     *
     * Rules:
     * - 'user' => content
     * - For each attribute element (Chunk):
     *   - If prefix is 'cas' or empty => key is localName
     *   - Else => key is "prefix:localName"
     *   - Value is the element's textContent
     *   - If multiple values for the same key, collect into array
     *
     * @param \SimpleSAML\CAS\XML\AuthenticationSuccess|\SimpleSAML\Slate\XML\AuthenticationSuccess $message
     *        The authentication success message to parse
     * @return array{
     *   0: \SimpleSAML\XMLSchema\Type\Interface\ValueTypeInterface,
     *   1: array<string, list<string>>
     * }
     */
    private function parseAuthenticationSuccess(CasAuthnSuccess|SlateAuthnSuccess $message): array
    {
        /** @var array<string, list<string>> $result */
        $result = [];

        // user -> content
        $user = $message->getUser()->getContent();

        // attributes -> elements (array of SimpleSAML\XML\Chunk)
        $attributes = $message->getAttributes();
        /** @var list<\SimpleSAML\XML\Chunk> $elements */
        $elements = $attributes->getElements();

        foreach ($elements as $chunk) {
            // Safely extract localName, prefix, and DOMElement from the Chunk
            $localName = $chunk->getLocalName();
            $prefix = $chunk->getPrefix();
            // DOMElement carrying the actual text content
            $xmlElement = $chunk->getXML();

            if (!$localName) {
                continue; // skip malformed entries
            }

            // Key selection rule
            $key = ($prefix === '' || $prefix === 'cas')
                ? $localName
                : ($prefix . ':' . $localName);

            $value = trim($xmlElement->textContent ?? '');

            // Collect values (single or multi)
            $result[$key] ??= [];
            $result[$key][] = $value;
        }

        // (DOMElement instances under cas:authenticationSuccess, outside cas:attributes)
        $this->parseAuthenticationSuccessMetadata($message, $result);

        return [$user, $result];
    }


    /**
     * Parse metadata elements from AuthenticationSuccess message and add them to attributes array
     *
     * @param \SimpleSAML\CAS\XML\AuthenticationSuccess|\SimpleSAML\Slate\XML\AuthenticationSuccess $message
     *        The authentication success message
     * @param array<string,list<string>> &$attributes Reference to attributes array to update
     * @return void
     */
    private function parseAuthenticationSuccessMetadata(
        CasAuthnSuccess|SlateAuthnSuccess $message,
        array &$attributes,
    ): void {
        if (!method_exists($message, 'getElements')) {
            // Either bail out or use a fallback
            return;
        }

        $metaElements = $message->getElements();

        foreach ($metaElements as $element) {
            if (!$element instanceof Chunk) {
                continue;
            }

            $localName = $element->getLocalName();
            $prefix    = $element->getPrefix();

            if ($localName === '') {
                continue;
            }

            // For metadata elements we do NOT special-case 'cas':
            // we always use "prefix:localName" when there is a prefix,
            // and just localName when there is none.
            $key = ($prefix === '')
                ? $localName
                : ($prefix . ':' . $localName);

            $value = trim($element->getXML()->textContent ?? '');

            $attributes[$key] ??= [];
            $attributes[$key][] = $value;
        }
    }


    /**
     * Parse metadata attributes from CAS response XML using configured XPath queries
     *
     * @param \DOMDocument $dom The XML document containing CAS response
     * @return array<string,array<string>> Array of metadata attribute names and values
     */
    private function parseQueryAttributes(DOMDocument $dom): array
    {
        $root = $dom->documentElement;
        if (!$root instanceof DOMElement) {
            return [];
        }

        $xPath = XPath::getXPath($root, true);

        $metadata = [];
        $casattributes = $this->casConfig['attributes'] ?? null;
        if (!is_array($casattributes)) {
            return $metadata;
        }

        /** @var list<\DOMElement> $authnNodes */
        $authnNodes = XPath::xpQuery($root, 'cas:authenticationSuccess', $xPath);
        /** @var \DOMElement|null $authn */
        $authn = $authnNodes[0] ?? null;

        // Some have attributes in the xml - attributes is a list of XPath expressions to get them
        foreach ($casattributes as $name => $query) {
            $marker = 'cas:authenticationSuccess/';

            if (isset($query[0]) && $query[0] === '/') {
                // Absolute XPath
                if (strpos($query, $marker) !== false && $authn instanceof \DOMElement) {
                    $originalQuery = $query;
                    $query = substr($query, strpos($query, $marker) + strlen($marker));
                    Logger::info(sprintf(
                        'CAS client: rewriting absolute CAS XPath for "%s" from "%s" to relative "%s"',
                        $name,
                        $originalQuery,
                        $query,
                    ));
                    $nodes = XPath::xpQuery($authn, $query, $xPath);
                } else {
                    // Keep absolute; evaluate from document root
                    $nodes = XPath::xpQuery($root, $query, $xPath);
                }
            } else {
                // Relative XPath; prefer evaluating under authenticationSuccess if available
                $context = $authn instanceof DOMElement ? $authn : $root;
                $nodes = XPath::xpQuery($context, $query, $xPath);
            }

            foreach ($nodes as $n) {
                $metadata[$name][] = trim($n->textContent);
            }

            Logger::debug(sprintf(
                'CAS client: parsed metadata %s => %s',
                $name,
                json_encode($metadata[$name] ?? []),
            ));
        }

        return $metadata;
    }
}
