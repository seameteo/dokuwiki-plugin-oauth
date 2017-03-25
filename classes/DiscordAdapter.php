<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Discord;

/**
 * Class DiscordAdapter
 *
 * Authentication scope needed: identify email
 *
 * @package OAuth\Plugin
 */
class DiscordAdapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'email', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $result = $JSON->decode($this->oAuth->request('/users/@me'));
        
        // Check if user's email is verified
        if (!$result['verified']) {
            msg('Your account is not verified.', -1);
            return array();
        }

        // Export User Data.
        // Discord's username will include Unicode, so it might be wrong on register.
        $data['user'] = $result['username'];
        $data['name'] = $result['username'];
        $data['mail'] = $result['email'];

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(Discord::SCOPE_IDENTIFY, Discord::SCOPE_EMAIL);
    }

}