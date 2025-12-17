# Using the CAS authentication source with SimpleSAMLphp

This is completely based on the original cas authentication,
the only difference is this is authentication module and not a script.

## Setting up the CAS authentication module

Adding an authentication source

Example authsource.php:

```php
'example-cas' => [
    'cas:CAS',
    'cas' => [
        'login' => 'https://cas.example.com/login',
        'validate' => 'https://cas.example.com/validate',
        'logout' => 'https://cas.example.com/logout'
    ],
    'ldap' => [
        'servers' => 'ldaps://ldaps.example.be:636/',
        'enable_tls' => true,
        'searchbase' => 'ou=people,dc=org,dc=com',
        'searchattributes' => 'uid',
        'attributes' => ['uid','cn'],
        'priv_user_dn' => 'cn=simplesamlphp,ou=applications,dc=org,dc=com',
        'priv_user_pw' => 'password',
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
    'serviceValidate' => 'https://cas.example.com/serviceValidate',
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
        'uid'       => 'cas:user',
        'mail'      => 'cas:attributes/cas:mail',
    
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
        'uid' => 'cas:user',
        'sn' => 'cas:attributes/cas:sn',
        'givenName' => 'cas:attributes/cas:firstname',
        'mail' => 'cas:attributes/cas:mail',
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
