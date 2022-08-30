Using the CAS authentication source with SimpleSAMLphp
==========================================================

This is completely based on the original cas authentication, 
the only diffrence is this is authentication module and not a script.

Setting up the CAS authentication module
----------------------------------

Adding a authentication source

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

CAS V3 (since 2017) supports querying attributes. Those have to be published
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
        'uid' => '/cas:serviceResponse/cas:authenticationSuccess/cas:user',
        'sn' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:sn',
        'givenName' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:firstname',
        'mail' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:mail',
    ],
],
```

and even some custom attributes if they're set:

```php
'customabc' => '/cas:serviceResponse/cas:authenticationSuccess/custom:abc',
```

You'll probably want to avoid querying LDAP for attributes:
set `ldap` to a `null`:

```php
'example-cas' => [
    'cas:CAS',
    'cas' => [
        ...
],
'ldap' => null,
```
