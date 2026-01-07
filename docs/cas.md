# Using the CAS authentication source with SimpleSAMLphp

This is completely based on the original CAS authentication;
the only difference is this is an authentication module, not a script.

## Setting up the CAS authentication module

### Adding an authentication source

In new deployments using ldap v2.5+, configure LDAP as a separate authsource in the ldap module and reference it by id from CAS.

Example authsource.php:

```php
'example-cas' => [
    'cas:CAS',
    'cas' => [
        'login'    => 'https://cas.example.com/login',
        'validate' => 'https://cas.example.com/validate', // CAS v2
        'logout'   => 'https://cas.example.com/logout',
    ],
    'ldap' => [
        'authsource' => 'ldap-backend',
    ],
],

// LDAP authsource (dnpattern mode)
'ldap-backend' => [
    'ldap:Ldap',

    // REQUIRED in v2.5: one or more LDAP URLs
    'connection_string' => 'ldaps://ldap.example.com',

    // Optional extras
    'encryption' => 'ssl',
    'version'    => 3,
    'options'    => [
        'network_timeout' => 3,
        'referrals'       => false,
    ],

    // Dnpattern mode (no search)
    'dnpattern'     => 'uid=%username%,cn=people,dc=example,dc=com',
    'search.enable' => false,

    // 'attributes' => ['uid', 'cn', 'mail'],
]
```

OR:

```php
'example-cas' => [
    'cas:CAS',
    'cas' => [
        'login'    => 'https://cas.example.com/login',
        'serviceValidate' => 'https://cas.example.com/serviceValidate', // CAS v3
        'logout'   => 'https://cas.example.com/logout',
    ],
    'ldap' => [
        'authsource' => 'ldap-backend',
    ],
],

// LDAP authsource (search mode)
'ldap-backend' => [
    'ldap:Ldap',
    'connection_string' => 'ldaps://ldap1.example.com ldaps://ldap2.example.com',
    'search' => [
        'username' => 'cn=simplesamlphp,ou=apps,dc=example,dc=com',
        'password' => 'secret',
        'base'     => ['ou=people,dc=example,dc=com'],
        'filter'   => '(uid=%username%)',
        'scope'    => 'sub',
    ],
    'attributes'        => ['*'],
    'attributes.binary' => ['jpegPhoto'],
    'timeout'           => 3,
    'options'           => [
        'network_timeout' => 3,
        'referrals'       => false,
    ],
],
```

## Querying Attributes

CAS v3 (since 2017) supports querying attributes. Those have to be published
for the service you're calling. Here the service publishes `sn`, `firstName`
and `mail`.

To get them, call `serviceValidate`, either directly:

```php
'cas' => [
    'serviceValidate' => 'https://cas.example.com/serviceValidate', // CAS v3
]
```

Or you might have to call serviceValidate for Protocol 3 via **/p3/**:

```php
'cas' => [
    'serviceValidate' => 'https://cas.example.com/p3/serviceValidate',
]
```

### Optional: Enabling Slate extensions

Some deployments include vendor‑specific fields (for example `slate:*`) in CAS responses.
You can opt in to Slate support:

```php
'cas' => [
    // ...
    'serviceValidate' => 'https://cas.example.com/p3/serviceValidate',
    // Enable Slate support (optional)
    'slate.enabled' => true,

    // Optional XPath-based attribute mappings
    'attributes' => [
        // Standard CAS attributes
        'uid'  => 'cas:user',
        'mail' => 'cas:attributes/cas:mail',

        // Slate namespaced attributes inside cas:attributes
        'slate_person' => 'cas:attributes/slate:person',
        'slate_round'  => 'cas:attributes/slate:round',
        'slate_ref'    => 'cas:attributes/slate:ref',

        // Some deployments also place vendor elements at the top level
        'slate_person_top' => '/cas:serviceResponse/cas:authenticationSuccess/slate:person',
    ],
],
```

which would return something like

```xml
<cas:authenticationSuccess>
    <cas:user>jdoe</cas:user>
    <cas:attributes>
        <cas:credentialType>UsernamePasswordCredential</cas:credentialType>
        <cas:isFromNewLogin>false</cas:isFromNewLogin>
        <cas:mail>john.doe@example.com</cas:mail>
        <cas:authenticationDate>2021-01-19T08:38:49.624+01:00[Europe/Paris]</cas:authenticationDate>
        <cas:authenticationMethod>LdapAuthenticationHandler</cas:authenticationMethod>
        <cas:firstName>John</cas:firstName>
        <cas:successfulAuthenticationHandlers>LdapAuthenticationHandler</cas:successfulAuthenticationHandlers>
        <cas:longTermAuthenticationRequestTokenUsed>false</cas:longTermAuthenticationRequestTokenUsed>
        <cas:sn>Doe</cas:sn>
        </cas:attributes>
</cas:authenticationSuccess>
```

So we can query for attributes in `authsources.php`, providing the XPath
for each value:

```php
'cas' => [
    'attributes' => [
        'uid'       => 'cas:user',
        'sn'        => 'cas:attributes/cas:sn',
        'givenName' => 'cas:attributes/cas:firstname',
        'mail'      => 'cas:attributes/cas:mail',
    ],
],
```

and even some custom attributes if they're set:

```php
'customabc' => 'custom:abc',
```

You'll probably want to avoid querying LDAP for attributes:
set `ldap` to `null`:

```php
'example-cas' => [
    'cas:CAS',
    'cas' => [
        ...
    ],
    'ldap' => null,
]
```

### Troubleshooting

- Mismatch between validate (v2) and serviceValidate (v3): ensure you use the correct endpoint for your CAS server.
- Attribute mappings: verify XPath keys match your CAS response (case‑sensitive).
- LDAP connection issues: confirm connection_string, credentials, and base DN; consider increasing `network_timeout` while testing.
