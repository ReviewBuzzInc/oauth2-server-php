<?php

/**
 * ReviewBuzz PDO Storage
 *
 * @category  CyberHULL
 * @package   Storage
 * @copyright Copyright (C) 2016 CyberHULL (www.cyberhull.com)
 * @author    Artem Petrusenko <artem.petrusenko@cyberhull.com>
 */

namespace OAuth2\Storage;

class RBPdoStorage extends Pdo
{
    protected $sb;

    /**
     * @var string RB Membership code which stored in the session
     */
    protected $sessionMembership;

    public function __construct($connection, $config)
    {
        parent::__construct($connection, $config);
        global $sb;
        $this->sb = $sb;
        $this->sessionMembership = isset($_SESSION[P('memberships')]) ? $_SESSION[P('memberships')] : null;
    }

    /**
     * Function returns default scope
     *
     * @param null|string $clientId client_id field from oauth_clients table
     * @return null|string A space-separated string of scopes or null
     */
    public function getDefaultScope($clientId = null)
    {
        $userId = $this->getUserId($clientId);

        // Default scope for both grant_type (authorization_code and client_credentials)
        $result = $this->loadClientScope($clientId);

        // In case when user id is stored in storage and grant_type equals client_credentials
        if ($userId !== null) {
            // Compare the values between membership scope and client scope and returns the matches
            $result = $this->prepareScope($this->getMembershipScope($userId), $result);

        // In case when user id is stored in session and grant_type equals authorization_code
        } elseif (!empty($this->sessionMembership)) {
            // Compare the values between membership scope and client scope and returns the matches
            $result = $this->prepareScope($this->getMembershipScope(null), $result);
        }

        return $result;
    }

    /**
     * Get membership scope
     *
     * @param string $userId RB user id
     * @return array|null A space-separated string of scopes or null
     */
    protected function getMembershipScope($userId)
    {
        $membership = null;

        // In case when user id is stored in storage
        if ($userId !== null) {
            $user = $this->sb->get('users')->getUser($userId);
            $membership = $user['memberships'];

        // In case when user id is stored in session
        } elseif (!empty($this->sessionMembership)) {
            $membership = $this->sessionMembership;
        }

        return $this->sb->get('api_membership_access_rule')->getScope($membership);
    }

    /**
     * Compare the values of two scope array and returns the matches
     *
     * @param string $firstScope A space-separated string of scopes
     * @param string $secondScope A space-separated string of scopes
     * @return null|string A space-separated string of scopes or null
     */
    protected function prepareScope($firstScope, $secondScope)
    {
        $firstScope = explode(' ', trim($firstScope));
        $secondScope = explode(' ', trim($secondScope));
        $result = implode(' ', array_uintersect($firstScope, $secondScope, "strcasecmp"));
        if (empty($result)) {
            $result = null;
        }

        return $result;
    }

    /**
     * Get all data from db about client
     *
     * @param string $clientId client_id field from oauth_clients table
     * @return array information about client
     */
    public function getClientDetails($clientId)
    {
        $query = "SELECT * FROM oauth_clients WHERE client_id = :client_id";
        $result = $this->sb->db->prepare($query);
        $result->execute(array(':client_id' => $clientId));
        $result = $result->fetch(\PDO::FETCH_ASSOC);
        $result['scope'] = $this->getDefaultScope($clientId);

        return $result;
    }

    /**
     * Get client scopes from db
     *
     * @param string $clientId client_id field from oauth_clients table
     * @return array|null A space-separated string of scopes or null
     */
    public function loadClientScope($clientId)
    {
        $query = "SELECT sb_oauth_scope.scope 
                FROM sb_oauth_client_scope, sb_oauth_scope, oauth_clients
                WHERE oauth_clients.client_id = :client_id
                AND sb_oauth_client_scope.oauth_client_id = oauth_clients.id 
                AND sb_oauth_client_scope.oauth_scope_id = sb_oauth_scope.id";
        $result = $this->sb->db->prepare($query);
        $result->execute(array(':client_id' => $clientId));
        $result = $result->fetchAll(\PDO::FETCH_COLUMN);
        $result = implode(" ", $result);
        if (empty($result)) {
            $result = null;
        }

        return $result;
    }

    /**
     * Get RB user id
     *
     * @param string $clientId client_id field from oauth_clients table
     * @return int|null
     */
    protected function getUserId($clientId)
    {
        $query = "SELECT user_id FROM oauth_clients WHERE client_id = :client_id";
        $result = $this->sb->db->prepare($query);
        $result->execute(array(':client_id' => $clientId));
        $result = $result->fetch(\PDO::FETCH_COLUMN);

        return $result ? $result : null;
    }
}
