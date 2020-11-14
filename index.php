<?php declare(strict_types = 1);

/**
 * Check if a provided string matches the IndieAuth criteria for a Client Identifier.
 * @see https://indieauth.spec.indieweb.org/#client-identifier
 * 
 * @TODO Check hostname restrictions
 * 
 * @param string $client_id The client ID provided by the OAuth Client
 * @return bool true if the value is allowed by IndieAuth
 */
function is_client_identifier(string $client_id): bool {
    return ($url_components = parse_url($client_id)) &&                     // Clients are identified by a URL.
        in_array($url_components['scheme'] ?? '', ['http', 'https']) &&     // Client identifier URLs MUST have either an https or http scheme,
        0 < strlen($url_components['path'] ?? '') &&                        // MUST contain a path component,
        false === strpos($url_components['path'], '/./') &&                 // MUST NOT contain single-dot
        false === strpos($url_components['path'], '/../') &&                // or double-dot path segments,
        false === isset($url_components['fragment']) &&                     // MUST NOT contain a fragment component,
        false === isset($url_components['user']) &&                         // MUST NOT contain a username
        false === isset($url_components['pass'])                            // or password component,
    ;
}

/**
 * Check if a provided string matches the IndieAuth criteria for a User Profile URL.
 * @see https://indieauth.spec.indieweb.org/#user-profile-url
 * 
 * @TODO Check hostname restrictions
 * 
 * @param string $profile_url The profile URL provided by the IndieAuth Client as me
 * @return bool true if the value is allowed by IndieAuth
 */
function is_profile_url(string $profile_url): bool {
    return ($url_components = parse_url($profile_url)) &&                   // Users are identified by a URL.
        in_array($url_components['scheme'] ?? '', ['http', 'https']) &&     // Profile URLs MUST have either an https or http scheme,
        0 < strlen($url_components['path'] ?? '') &&                        // MUST contain a path component,
        false === strpos($url_components['path'], '/./') &&                 // MUST NOT contain single-dot
        false === strpos($url_components['path'], '/../') &&                // or double-dot path segments,
        false === isset($url_components['fragment']) &&                     // MUST NOT contain a fragment component,
        false === isset($url_components['user']) &&                         // MUST NOT contain a username
        false === isset($url_components['pass']) &&                         // or password component,
        false === isset($url_components['port'])                            // and MUST NOT contain a port.
    ;
}

/**
 * Canonicalise URLs to be valid Special URLs.
 * 
 * A scheme (https) and path (/) will be added to the provided URL if either are missing.
 * This does not guarantee valid URLs as output, it just adds missing values.
 * 
 * @see https://indieauth.spec.indieweb.org/#url-canonicalization
 * 
 * @param string $possible_url A string value that is a possible URL, to be canonicalised
 * @return string the canonicalised URL
 */
function canonicalise_url(string $url): string {
    $url_components = parse_url($url);
    if (false === $url_components || false === isset($url_components['scheme'])) {
        $url = 'https://' . $url;
    }
    $url_components = parse_url($url);
    if (false === $url_components || false === isset($url_components['path'])) {
        $url = $url . '/';
    }
    return $url;
}

/**
 * Add (or overwrite) data in the query part of the URI. Used for building on redirection URIs.
 * 
 * @param string $uri The URI to add data on
 * @param array $query_data The data to be added onto the URI
 * @return string the modified URI
 */
function add_to_query(string $uri, array $query_data): string {
    [$uri, $fragment] = explode('#', $uri, 2) + [false, false];
    [$uri, $query] = explode('?', $uri, 2) + [false, false];
    if (false !== $query) {
        parse_str($query, $query_parts);
        $query_data = array_merge($query_parts, $query_data);
    }
    return $uri . '?' . http_build_query($query_data) . (false !== $fragment ? '#' . $fragment : '');
}

/**
 * Serve error responses to the client per RFC 6749 section 4.1.2.1.
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
 * 
 * @param string $redirect_uri The redirect URI provided by the OAuth Client
 * @param string $error_code The OAuth error code specified by the specification
 * @param string $error_description The description of what went wrong
 * @param string $state (optional) The state provided by the OAuth Client
 * @return void
 */
function error_response(string $redirect_uri, string $error_code, string $error_description, string $state = null): void {
    $error_query = ['error' => $error_code, 'error_description' => $error_description];
    if (null !== $state) $error_query['state'] = $state;
    header('HTTP/1.1 302 Found');
    header('Location: ' . add_to_query($redirect_uri, $error_query));
    exit();
}

/**
 * OAuth 2.0 tells us failures in the client identifier or redirection URI are solely communicated to the user.
 * 
 * @TODO redirect_uri validation
 * 
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1 For error guidance.
 */
$client_id = filter_input(INPUT_GET, 'client_id', FILTER_VALIDATE_URL);
$redirect_uri = filter_input(INPUT_GET, 'redirect_uri', FILTER_VALIDATE_URL);
if (false === is_string($client_id) || false === is_client_identifier($client_id) || false === is_string($redirect_uri)) {
    header('HTTP/1.1 400 Bad Request');
    $template = <<<'HTML'
<!doctype html>
<html lang="en-GB">
    <head>
        <meta charset="utf-8">
        <title>MinDee: Bad Request from Client</title>
    </head>
    <body>
        <h1>Bad Request from Client</h1>
        <p>The Client Identifier and/or return URL were send incorrectly. The values below were given.</p>
        <dl>
            <dt><code>client_id</code></dt>
            <dd>%s</dd>
            <dt><code>redirect_uri</code></dt>
            <dd>%s</dd>
        </dl>
    </body>
</html>
HTML;
    $client_id = null === $client_id ? 'None' : '<code>' . htmlspecialchars(filter_input(INPUT_GET, 'client_id', FILTER_UNSAFE_RAW)) . '</code>';
    $redirect_uri = null === $redirect_uri ? 'None' : '<code>' . htmlspecialchars(filter_input(INPUT_GET, 'redirect_uri', FILTER_UNSAFE_RAW)) . '</code>';
    echo sprintf($template, $client_id, $redirect_uri);
    exit();
}

/**
 * OAuth 2.0 limits what values are valid for state.
 * We check this first, because if valid, we want to send it along with other errors.
 * @see https://tools.ietf.org/html/rfc6749#appendix-A.5
 */
$state = filter_input(INPUT_GET, 'state', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^[\x20-\x7E]*$@']]);
if (false === $state) {
    error_response($redirect_uri, 'invalid_request', 'OAuth allows a limited set of characters within state, symbols outside of this range were used.');
}

/**
 * IndieAuth requires a response type of code.
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
 * @see https://indieauth.spec.indieweb.org/#authorization-request
 */
$response_type = filter_input(INPUT_GET, 'response_type', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^code$@']]);
if (null === $response_type) {
    error_response($redirect_uri, 'invalid_request', 'OAuth requires a response type, but none was provided.', $state);
}
if (false === $response_type) {
    error_response($redirect_uri, 'unsupported_response_type', 'IndieAuth requires a response type value of `code`.', $state);
}

/**
 * IndieAuth requires PKCE. This implementation supports only S256 for hashing.
 * 
 * @TODO Add length check to the code_challenge, this should be possible as MinDee only support S256.
 * 
 * @see https://tools.ietf.org/html/rfc7636#section-4.4.1
 * @see https://indieauth.spec.indieweb.org/#authorization-request
 */
$code_challenge = filter_input(INPUT_GET, 'code_challenge', FILTER_SANITIZE_STRING, ['options' => ['regexp' => '@^[A-Za-z0-9_-]+$@']]);
$code_challenge_method = filter_input(INPUT_GET, 'code_challenge_method', FILTER_UNSAFE_RAW);
if ('S256' !== $code_challenge_method) {
    error_response($redirect_uri, 'invalid_request', 'IndieAuth requires PKCE, but no valid code challenge method was provided. MinDee only supports S256.', $state);
}
if (false === is_string($code_challenge)) {
    error_response($redirect_uri, 'invalid_request', 'IndieAuth requires PKCE, but no valid code challenge was provided.', $state);
}

/**
 * OAuth 2.0 limits what values are valid for scope.
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 */
$scope = filter_input(INPUT_GET, 'scope', FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => '@^([\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*)?$@']]);
if (false === $scope) {
    error_response($redirect_uri, 'invalid_scope', 'OAuth requires scopes to follow a specific syntax, the provided scopes did not comply.');
}
$scopes = [];
if ($scope !== null && strlen($scope) > 0) {
    $scopes = explode(' ', $scope);
}

/**
 * IndieAuth allows for an optional me value to be provided.
 */
$me = filter_input(INPUT_GET, 'me', FILTER_UNSAFE_RAW);

/**
 * If a me value was provided, make sure it has been canonicalised and validated before using it.
 */
if (!is_string($me) || !is_profile_url($me = canonicalise_url($me))) {
    $me = '';
}


?><!doctype html>
<html lang="en-GB">
    <head>
        <meta charset="utf-8">
        <title>Authorize MinDee</title>
        <style>
        </style>
    </head>
    <body>
        <form method="POST">
            <p>You are logging in to <span class="url"><?= htmlspecialchars($client_id) ?></span>.</p>
            <p>The URL <label for="me">you will be identified as</label> is:</p>
            <input type="url" name="me" id="me" value="<?= htmlspecialchars($me) ?>">
            <p>The following scopes will be granted, uncheck any you do not wish to grant:</p>
            <ul>
                <li><label for="scope_profile"><input type="checkbox" name="scope[]" id="scope_profile" value="profile"<?= in_array('profile', $scopes)?' checked':'' ?>> profile</label></li>
                <li><label for="scope_email"><input type="checkbox" name="scope[]" id="scope_email" value="email"<?= in_array('email', $scopes)?' checked':'' ?>> email</label></li>
    <?php foreach ($scopes as $item): if ($item !== 'profile' && $item !== 'email'): ?>
                <li><input type="checkbox" name="scope[]" value="<?= htmlspecialchars($item) ?>" checked> <?= htmlspecialchars($item) ?></li>
    <?php endif; endforeach; ?>
                <li><label for="custom_scopes">Custom (space delimited):</label> <input type="text" name="custom_scopes" id="custom_scopes"></li>
            </ul>
            <p>The following profile will be shared if the profile and optionally email scopes are granted:</p>
            <label for="profile_name">Name:</label>
            <input type="text" name="profile_name" id="profile_name">
            <label for="profile_photo">Avatar URL:</label>
            <input type="url" name="profile_photo" id="profile_photo">
            <label for="profile_url">Homepage URL:</label>
            <input type="url" name="profile_url" id="profile_url">
            <label for="profile_email">Email address:</label>
            <input type="email" name="profile_email" id="profile_email">
            <p>You will be redirected to <span class="url"><?= htmlspecialchars($redirect_uri) ?></span> from here.</p>
            <button type="submit" name="deny">Cancel</button>
            <label for="password">Password:</label>
            <input type="password" name="password" id="password">
            <button type="submit">Authorize</button>
        </form>
    </body>
</html>