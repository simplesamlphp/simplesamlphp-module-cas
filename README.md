# CAS module

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-cas/actions/workflows/php.yml/badge.svg)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-cas/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-cas)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-cas/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-cas/?branch=master)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-cas/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-cas)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-cas/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-cas)

## Install

Install with composer

```bash
    vendor/bin/composer require simplesamlphp/simplesamlphp-module-cas
```

## Configuration

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `cas` to true:

```php
'module.enable' => [
    'cas' => true,
    …
],
```
