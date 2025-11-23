<?php

declare(strict_types=1);

$config = [
    'admin' => [
        'core:AdminPassword',
    ],
    'something' => [
        'cas:CAS',
        'cas' => [
            'login' => 'https://example.org/login',
            'validate' => 'https://example.org/validate',
        ],
        'ldap' => [],
    ],
    'casserver' => [
        'cas:CAS',
        'cas' => [
            'login' => 'https://ugrad.apply.example.edu/account/cas/login',
            'serviceValidate' => 'https://ugrad.apply.example.edu/account/cas/serviceValidate',
            'logout' => 'https://ugrad.apply.example.edu/account/cas/logout',
            'attributes' => [
                'uid' => 'cas:user',
                // target the intended person under cas:attributes
                'person' => 'cas:attributes/slate:person',
                // if you still want to capture the top-level one, keep a separate key:
                'person_top' => 'slate:person',
                'sn' => 'cas:attributes/cas:sn',
                'givenName' => 'cas:attributes/cas:firstname',
                'mail' => 'cas:attributes/cas:mail',
                'eduPersonPrincipalName' => 'cas:attributes/cas:eduPersonPrincipalName',
            ],
        ],
        'ldap' => [],
    ],
    'casserver_legacy' => [
        'cas:CAS',
        'cas' => [
            'login' => 'https://ugrad.apply.example.edu/account/cas/login',
            'serviceValidate' => 'https://ugrad.apply.example.edu/account/cas/serviceValidate',
            'logout' => 'https://ugrad.apply.example.edu/account/cas/logout',
            'attributes' => [
                'uid' => '/cas:serviceResponse/cas:authenticationSuccess/cas:user',
                // target the intended person under cas:attributes
                'person' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/slate:person',
                // if you still want to capture the top-level one, keep a separate key:
                'person_top' => '/cas:serviceResponse/cas:authenticationSuccess/slate:person',
                'sn' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:sn',
                'givenName' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:firstname',
                'mail' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:mail',
                // phpcs:ignore Generic.Files.LineLength.TooLong
                'eduPersonPrincipalName' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:eduPersonPrincipalName',
            ],
        ],
        'ldap' => [],
    ],
    'casserver_auto_map' => [
        'cas:CAS',
        'cas' => [
            'login' => 'https://ugrad.apply.example.edu/account/cas/login',
            'serviceValidate' => 'https://ugrad.apply.example.edu/account/cas/serviceValidate',
            'logout' => 'https://ugrad.apply.example.edu/account/cas/logout',
        ],
        'ldap' => [],
    ],
];
