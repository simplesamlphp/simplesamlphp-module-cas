<?php

/**
 * Handle linkback() response from CAS.
 */

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Module\cas\Auth\Source\CAS;

if (!isset($_GET['stateID'])) {
    throw new Error\BadRequest('Missing stateID parameter.');
}
$state = Auth\State::loadState($_GET['stateID'], CAS::STAGE_INIT);

if (!isset($_GET['ticket'])) {
    throw new Error\BadRequest('Missing ticket parameter.');
}
$state['cas:ticket'] = (string) $_GET['ticket'];

// Find authentication source
assert(array_key_exists(CAS::AUTHID, $state));
$sourceId = $state[CAS::AUTHID];

/** @var \SimpleSAML\Module\cas\Auth\Source\CAS|null $source */
$source = Auth\Source::getById($sourceId);
if ($source === null) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$source->finalStep($state);
