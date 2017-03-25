<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Service\Exception\InvalidServiceConfigurationException;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Discord extends AbstractService
{

    /**
     * Discord OAuth2
     * More referenes: https://discordapp.com/developers/docs/topics/oauth2
     */

    // Scopes
    const SCOPE_CONNECTIONS  = 'connections';       // Get user's other connections
    const SCOPE_EMAIL        = 'email';             // Get email infomation
    const SCOPE_IDENTIFY     = 'identify';          // Get user infomation
    const SCOPE_GUILDS       = 'guilds';            // Listing user's Server
    const SCOPE_GUILDS_JOIN  = 'guilds.join';       // Join to Server
    const SCOPE_GDM_JOIN     = 'gdm.join';          // Join to DM
    const SCOPE_WEBHOOK      = 'webhook.incoming';  // Webhook with token
    
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://discordapp.com/api/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://discordapp.com/api/oauth2/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://discordapp.com/api/oauth2/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        unset($data['access_token']);

        $token->setLifeTime($data['expires_in']);
        unset($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        $token->setExtraParams($data);

        return $token;
    }
}
