<?php

/**
 * CAS Authentication
 *
 * This plugin augments the RoundCube login page with the ability to authenticate
 * to a CAS server, which enables logging into RoundCube with identities
 * authenticated by the CAS server and acts as a CAS proxy to relay authenticated
 * credentials to the IMAP backend.
 *
 * The vast majority of this plugin was written by Alex Li. David Warden modified
 * it to be an optional authentication method that can work with stock Roundcube
 * version 0.8.
 *
 * @version 0.8.0
 * @author David Warden (dfwarden@gmail.com)
 * @author Alex Li (li@hcs.harvard.edu)
 * @contributor Julien Gribonvald (julien.gribonvald@recia.fr)
 * @contributor Maxime Bossard (maxime.bossard@recia.fr)
 * @contributor Pierre Lejeune (pierre.lejeune@recia.fr)
 */

use CasAuthn\CasClientInitializer;
class cas_authn extends rcube_plugin
{

    private $cas_inited;

    /**
     * Initialize plugin
     *
     */
    function init()
    {
        // initialize plugin fields
        $this->cas_inited = false;

        // load plugin configuration
        $this->load_config();

        // add application hooks
        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('storage_connect', array($this, 'imap_connect'));
        $this->add_hook('smtp_connect', array($this, 'smtp_connect'));
        $this->add_hook('sieverules_connect', array($this, 'sieverules_connect'));
        $this->add_hook('template_object_loginform', array($this, 'add_cas_login_html'));
    }

    /**
     * Handle plugin-specific actions
     * These actions are handled at the startup hook rather than registered as
     * custom actions because the user session does not necessarily exist when
     * these actions need to be handled.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */

    function startup(array $args): array
    {
        if ($args['action'] == 'pgtcallback') {
            $this->handlePgtCallback();
        } elseif ($args['task'] == 'logout') {
            $this->handleLogout();
        } elseif ($args['action'] == 'caslogin') {
            $this->handleCasLogin();
        }

        return $args;
    }

    /**
     * Intercept logout action.
     * We unfortunately cannot use the logout_after plugin hook because it is
     * executed after session is destroyed.
     */
    private function handleLogout(): void
    {
        $this->cas_init();

        if (!phpCAS::isSessionAuthenticated()) {
            return;
        }

        $RCMAIL = rcmail::get_instance();
        $RCMAIL->logout_actions();
        $RCMAIL->kill_session();
        $RCMAIL->plugins->exec_hook('logout_after', $userdata);
        phpCAS::logout();
        exit;
    }

    /**
     * Intercept PGT callback action from CAS server.
     * Stores the PGT if present, then ends the script - nothing else to do.
     */
    private function handlePgtCallback(): void
    {
        $this->cas_init();

        try {
            phpCAS::forceAuthentication();
        } catch (Exception $e) {
        }

        exit;
    }

    /**
     * Intercept CAS login: force CAS authentication, then log the user
     * into Roundcube and redirect to the mail task.
     */
    private function handleCasLogin(): void
    {
        $RCMAIL = rcmail::get_instance();
        $cfg = $RCMAIL->config->all();

        $this->cas_init();

        // Look for _url GET variable and update FixedServiceURL if present to enable deep linking.
        $query = array();
        if ($url = rcube_utils::get_input_value('_url', rcube_utils::INPUT_GET)) {
            phpCAS::setFixedServiceURL($this->generate_url(array('action' => 'caslogin', '_url' => $url)));
        }

        // Force the user to log in to CAS, using a redirect if necessary.
        phpCAS::forceAuthentication();

        // If control reaches this point, user is authenticated to CAS.
        $user = phpCAS::getUser();
        $pass = $this->resolveImapPassword($cfg);

        // Do Roundcube login actions
        $RCMAIL->login($user, $pass, $RCMAIL->autoselect_host());
        $RCMAIL->session->remove('temp');
        // We don't change the session id which is the CAS login ST.
        $RCMAIL->session->set_auth_cookie();

        // log successful login
        $RCMAIL->log_login();

        // allow plugins to control the redirect url after login success
        $redir = $RCMAIL->plugins->exec_hook('login_after', $query + array('_task' => 'mail'));
        unset($redir['abort'], $redir['_err']);

        // send redirect, otherwise control will reach the mail display and fail because the
        // IMAP session was already started by $RCMAIL->login()
        $RCMAIL->output->redirect($redir);
    }

    /**
     * Retrieve the password to authenticate against the IMAP backend:
     * either a Proxy Ticket (proxy mode) or the configured 'masteruser' password.
     */
    private function resolveImapPassword(array $cfg) : string
    {
        if (!$cfg['cas_proxy']) {
            return $cfg['cas_imap_password'];
        }

        $_SESSION['cas_pt'][php_uname('n')] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);

        return $_SESSION['cas_pt'][php_uname('n')];
    }


    /**
     * Inject IMAP authentication credentials
     * If you are using this plugin in proxy mode, this will set the password
     * to be used in RCMAIL->imap_connect to a Proxy Ticket for cas_imap_name.
     * If you are not using this plugin in proxy mode, it will do nothing.
     * If you are using normal authentication, it will do nothing.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function imap_connect($args)
    {
        // retrieve configuration
        $cfg = rcmail::get_instance()->config->all();

        // RoundCube is acting as CAS proxy
        if ($cfg['cas_proxy']) {

            // check expiration of PT caching time
            $ptExpired = false;
            if (time() - $_SESSION['cas_pt_time'][php_uname('n')] > $cfg['cas_imap_pt_expiration_time']) {
                // Clear PT caching if expired
                $_SESSION['cas_pt'][php_uname('n')] = false;
                $ptExpired = true;
            }

            // a proxy ticket has been retrieved, the IMAP server caches proxy tickets, and this is the first connection attempt
            if ($_SESSION['cas_pt'][php_uname('n')] && $cfg['cas_imap_caching'] && $args['attempt'] == 1) {
                // use existing proxy ticket in session
                $args['pass'] = $_SESSION['cas_pt'][php_uname('n')];
            } // no proxy tickets have been retrieved, the IMAP server doesn't cache proxy tickets, or the first connection attempt has failed
            else {
                // initialize CAS client
                $this->cas_init();
                // If PT expired we check the authentication to load all auth infos wich lays in session
                if ($ptExpired) {
                    phpCAS::checkAuthentication();
                }

                // if CAS session exists, use that.
                // retrieve a new proxy ticket and store it in session
                if (phpCAS::isSessionAuthenticated()) {
                    $err_code = null;
                    $output = null;
                    $_SESSION['cas_pt'][php_uname('n')] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
                    //add PT caching time in session
                    $_SESSION['cas_pt_time'][php_uname('n')] = time();
                    $args['pass'] = $_SESSION['cas_pt'][php_uname('n')];
                    error_log("New PT : " . $args['pass']);
                    if ($output) {
                        error_log("Error while retrieving new PT: " . $output);
                    }
                }
            }

            // enable retry on the first connection attempt only
            if ($args['attempt'] <= 1) {
                $args['retry'] = true;
            }
        }
        return $args;
    }

    /**
     * Inject SMTP authentication credentials
     * If you are using this plugin in proxy mode, this will set the password
     * to be used in RCMAIL->smtp->connect to a new Proxy Ticket for cas_smtp_name.
     * If you are not using this plugin in proxy mode, it will do nothing.
     * If you are using normal authentication, it will do nothing.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function smtp_connect($args)
    {
        // retrieve configuration
        $cfg = rcmail::get_instance()->config->all();

        // RoundCube is acting as CAS proxy and performing SMTP authn
        if ($cfg['cas_proxy'] && $args['smtp_user'] && $args['smtp_pass']) {
            // initialize CAS client
            $this->cas_init();

            // retrieve a new proxy ticket and use it as SMTP password
            // Without forceAuthentication() then retrievePT() fails.
            if (phpCAS::isSessionAuthenticated()) {
                phpCAS::forceAuthentication();
                $args['smtp_pass'] = phpCAS::retrievePT($cfg['cas_smtp_name'], $err_code, $output);
            }
        }

        return $args;
    }

    /**
     * Inject Sieve authentication credentials
     * If you are using this plugin in proxy mode, this will set the password
     * to be used in sieverules_connect() to a new Proxy Ticket for opt_cas_imap_name.
     * If you are not using this plugin in proxy mode, it will do nothing.
     * If you are using normal authentication, it will do nothing.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function sieverules_connect($args)
    {
        // retrieve configuration
        $cfg = rcmail::get_instance()->config->all();

        // RoundCube is acting as CAS proxy
        if ($cfg['opt_cas_proxy']) {
            // initialize CAS client
            $this->cas_init();

            // retrieve a new proxy ticket and use it as SMTP password
            // Without forceAuthentication() then retrievePT() fails.
            if (phpCAS::isSessionAuthenticated()) {
                phpCAS::forceAuthentication();
                $args['password'] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
            }
        }

        return $args;
    }

    /**
     * Prepend link to CAS login above the Roundcube login form if the user would like to
     * login with CAS.
     */
    function add_cas_login_html($args)
    {
        $RCMAIL = rcmail::get_instance();
        $this->add_texts('localization');
        // retrieve configuration
        $cfg = rcmail::get_instance()->config->all();

        // Force CAS authn?
        if ($cfg["cas_force"]) {
            $RCMAIL->output->redirect(array('action' => 'caslogin'));
        }

        $caslogin_content = html::div(array(
            'style' => 'border-bottom: 1px dotted #000; text-align: center; padding-bottom: 1em; margin-bottom: 1em;'),
            html::a(array(
                'href' => $this->generate_url(array('action' => 'caslogin')),
                'title' => $this->gettext('casloginbutton')),
                $this->gettext('casloginbutton')
            )
        );
        $args['content'] = $caslogin_content . $args['content'];
        return $args;
    }

    /**
     * Initialize CAS client
     *
     */
    private function cas_init(): void
    {
        require_once __DIR__ . '/vendor/autoload.php';
        if ($this->cas_inited) {
            return;
        }

        $old_session = $_SESSION;

        if (!isset($_SESSION['session_inited'])) {
            // If the session isn't 'inited' by CAS
            // We destroy the session to the CAS client be able to init it
            session_destroy();
        }

        $RCMAIL = rcmail::get_instance();
        $cfg = $RCMAIL->config->all();

        $postAuthenticateCallback = function ($ticket) use ($old_session) {
            if (!isset($_SESSION['session_inited'])) {
                $_SESSION = array_merge($_SESSION, $old_session);
                $_SESSION['session_inited'] = true;
            }
        };

        (new CasClientInitializer($cfg, $RCMAIL->session))->initialize(
            $this->generate_url(array('action' => 'caslogin')),
            $this->generate_url(array('action' => 'pgtcallback')),
            $postAuthenticateCallback,
            array($this, 'handleSingleLogout')
        );

        if (is_null($_SESSION)) {
            rcmail::get_instance()->kill_session();
        }

        if (!isset($_SESSION['session_inited'])) {
            // If the session isn't 'inited' by CAS
            // we keep the last session
            $_SESSION = array_merge($_SESSION, $old_session);
            $_SESSION['session_inited'] = true;
        }

        phpCAS::forceAuthentication();

        $this->cas_inited = true;
    }

    /**
     * Handle the logout comming from CAS server (globalLogout)
     *
     * @param ticket is the ST name given by CAS for the user when CAS was requested to authenticate on Roundcube.
     */
    function handleSingleLogout($ticket)
    {
        $RCMAIL = rcmail::get_instance();
        $RCMAIL->session->destroy($ticket);
    }

    /**
     * Build full URLs to this instance of RoundCube for use with CAS servers
     *
     * @param array $params url parameters as key-value pairs
     * @return string full Roundcube URL
     */
    private function generate_url($params)
    {
        $s = ($_SERVER['HTTPS'] == 'on') ? 's' : '';
        $protocol = $this->strleft(strtolower($_SERVER['SERVER_PROTOCOL']), '/') . $s;

        /* Derrière un reverse proxy (Lando, load balancer...), SERVER_PORT
        * reflète le port interne, pas le port public - on se fie à
        * X-Forwarded-Port quand il est présent (non validé contre une
        * whitelist d'IP de proxy, comme le $_SERVER['HTTPS'] ci-dessus).
        */

        $forwarded_port = $_SERVER['HTTP_X_FORWARDED_PORT'] ?? $_SERVER['SERVER_PORT'];
        $standard_port = $s == 's' ? '443' : '80';
        $port = ($forwarded_port == $standard_port) ? '' : (':' . $forwarded_port);
        $path = $this->strleft($_SERVER['REQUEST_URI'], '?');
        $parsed_params = '';
        $delm = '?';
        foreach (array_reverse($params) as $key => $val) {
            if (!empty($val)) {
                $parsed_key = $key[0] == '_' ? $key : '_' . $key;
                $parsed_params .= $delm . urlencode($parsed_key) . '=' . urlencode($val);
                $delm = '&';
            }
        }
        $cfg = rcmail::get_instance()->config->all();
        if ($cfg['cas_webmail_server_name']) {
            $serverName = $cfg['cas_webmail_server_name'];
        } else {
            $serverName = $_SERVER['SERVER_NAME'];
        }
        return $protocol . '://' . $serverName . $port . $path . $parsed_params;
    }

    private function strleft($s1, $s2)
    {
        $length = strpos($s1, $s2);
        if ($length) {
            return substr($s1, 0, $length);
        } else {
            return $s1;
        }
    }
}

?>
