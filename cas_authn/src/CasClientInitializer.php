<?php

namespace CasAuthn;
use phpCAS;
use SessionHandlerInterface;

/**
 * Configures the phpCAS client for cas_authn: server connection, proxy vs
 * client mode, callbacks, SSL validation, login/logout URLs. Kept separate
 * from Roundcube's own session reconciliation, which stays in
 * cas_authn::cas_init().
 */
class CasClientInitializer
{
    public function __construct(
        private readonly array                   $cfg,
        private readonly SessionHandlerInterface $sessionHandler
    )
    {
    }

    public function initialize(
        string   $serviceUrl,
        string   $pgtCallbackUrl,
        callable $postAuthenticateCallback,
        callable $singleSignoutCallback
    ): void
    {

        if ($this->cfg['cas_debug']) {
            phpCAS::setDebug($this->cfg['cas_debug_file']);
        }

        $this->initializeClient($pgtCallbackUrl);

        phpCAS::setPostAuthenticateCallback($postAuthenticateCallback);
        phpCAS::setSingleSignoutCallback($singleSignoutCallback);
        phpCAS::setFixedServiceURL($serviceUrl);

        $this->initializeLogoutHandling();
        $this->initializeSslValidation();

        phpCAS::setServerLoginURL($this->cfg['cas_login_url']);
        phpCAS::setServerLogoutURL($this->cfg['cas_logout_url']);
    }

    private function initializeClient(string $pgtCallbackUrl): void
    {
        $serviceBaseUrl = 'https://' . $this->cfg['cas_webmail_server_name'];

        if ($this->cfg['cas_proxy']) {
            phpCAS::proxy(
                CAS_VERSION_2_0,
                $this->cfg['cas_hostname'],
                $this->cfg['cas_port'],
                $this->cfg['cas_uri'],
                $serviceBaseUrl,
                false,
                $this->sessionHandler
            );
            phpCAS::setFixedCallbackURL($pgtCallbackUrl);
            phpCAS::setPGTStorageFile($this->cfg['cas_pgt_dir']);
        } else {
            phpCAS::client(
                CAS_VERSION_2_0,
                $this->cfg['cas_hostname'],
                $this->cfg['cas_port'],
                $this->cfg['cas_uri'],
                $serviceBaseUrl,
                false,
                $this->sessionHandler
            );
        }
    }

    private function initializeLogoutHandling(): void
    {
        if (empty($this->cfg['cas_clients'])) {
            phpCAS::handleLogoutRequests(true);
        } else {
            phpCAS::handleLogoutRequests(true, $this->cfg['cas_clients']);
        }
    }

    private function initializeSslValidation(): void
    {
        if ($this->cfg['cas_validation'] == 'self') {
            phpCAS::setCasServerCert($this->cfg['cas_cert']);
        } elseif ($this->cfg['cas_validation'] == 'ca') {
            phpCAS::setCasServerCACert($this->cfg['cas_cert']);
        } else {
            phpCAS::setNoCasServerValidation();
        }
    }
}