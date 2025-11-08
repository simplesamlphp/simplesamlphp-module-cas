<?php

declare(strict_types=1);

// phpcs:disable
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
                'sn' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:sn',
                'givenName' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:firstname',
                'mail' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:mail',
                'eduPersonPrincipalName' => '/cas:serviceResponse/cas:authenticationSuccess/cas:attributes/cas:eduPersonPrincipalName',
            ],
        ],
        'ldap' => [],
    ],
];
// phpcs:enable