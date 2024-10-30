<?php

/**
 * This file will create Custom Rest API End Points.
 */
const CC_MAX_IPS = 5;

class WP_Rest_Route
{
    public function __construct()
    {
        add_action('wp_ajax_get_settings', [$this, 'get_settings'], -999);
        add_action('wp_ajax_update_whitelist', [$this, 'update_whitelist'], -999);
        add_action('wp_ajax_save_settings', [$this, 'save_settings'], -999);
        add_action('wp_ajax_updateInstallClickFraud', [$this, 'updateInstallClickFraud'], -999);
    }

    public function get_settings()
    {
        if ($this->has_permission('get_settings')) {
            $clickcease_api_key = sanitize_text_field(get_option('clickcease_api_key', ''));
            $clickcease_domain_key = sanitize_text_field(get_option('clickcease_domain_key', ''));
            $secret_key = sanitize_text_field(get_option('clickcease_secret_key', ''));
            $remove_tracking = filter_var(get_option('clickcease_remove_tracking', ''), FILTER_VALIDATE_BOOLEAN);
            $botzappingAuth = sanitize_text_field(get_option('clickcease_bot_zapping_authenticated', ''));
            $whitelist = array_map('sanitize_text_field', get_option('clickcease_whitelist', []));
            $clientId = sanitize_text_field(get_option('clickcease_client_id', null));

            if (empty($clientId)) {
                $rtiService = new RTI_Service();
                $clientId = sanitize_text_field($rtiService->auth_with_botzapping($clickcease_api_key, $clickcease_domain_key, $secret_key,"get_settings"));
                if ($clientId) {
                    update_option('clickcease_client_id', $clientId);
                }
            }

            $response = [
                'authKey' => $clickcease_api_key,
                'domainKey' => $clickcease_domain_key,
                'secretKey' => $secret_key,
                'installClickFraud' => !$remove_tracking,
                'botzappingAuth' => $botzappingAuth,
                'whitelist' => $whitelist,
                'maxWhitelistLength' => CC_MAX_IPS,
                'clientId' => $clientId,
            ];

            $this->send_json_response(200, $response);
        } else {
            $this->send_json_response(403, 'Unauthorized access or security check failed');
        }
    }

    public function save_settings()
    {
        if ($this->has_permission('save_settings')) {
            $deactivate = sanitize_text_field($_POST['deactivate']);
            $res = Utils::getHttpSuccessResponse();

            if (empty($deactivate) || $deactivate === "undefined") {
                $formService = new FormService();
                $tag_hash_key = sanitize_text_field($_POST['domainKey']);
                $secret_key = sanitize_text_field($_POST['secretKey']);
                $api_key = sanitize_text_field($_POST['authKey']);
                $validAuth = true;
                $formService->validateDomainKey($tag_hash_key);
                $clientId = $formService->validateBotzappingAuth($api_key, $tag_hash_key, $secret_key,'save_settings');

                if (!$clientId) {
                    header('Status: ' . HTTPCode::BAD_REQUEST);
                    $res = Utils::getHttpErrorResponse(ResponseMessage::INVALID_KEYS);
                    $validAuth = false;
                } else {
                    update_option('clickcease_domain_key', $tag_hash_key);
                    update_option('secret_checked', true);
                    update_option('clickcease_client_id', $clientId);
                    $res = Utils::getHttpSuccessResponse(['clientId' => $clientId]);
                }

                if ($validAuth) {
                    update_option('clickcease_api_key', $api_key);
                    update_option('clickcease_secret_key', $secret_key);
                    LogService::logErrorCode(ErrorCodes::PLUGIN_INSTALL);
                }
            } else {
                $validAuth = !$deactivate;
                (new RTI_Service())->update_user_status(DomainState::BZ_PLUGIN_DEACTIVATED);
                LogService::logErrorCode(ErrorCodes::PLUGIN_REMOVE);
            }

            update_option('clickcease_bot_zapping_authenticated', $validAuth);
            update_option('cheq_invalid_secret', !$validAuth);
            echo $res;
        }

        wp_die();
    }

    public function updateInstallClickFraud()
    {
        if ($this->has_permission('updateInstallClickFraud')) {
            $installClickFraud = sanitize_text_field($_POST['installClickFraud']);
            $installClickFraud = filter_var($installClickFraud, FILTER_VALIDATE_BOOLEAN);
            update_option('clickcease_remove_tracking', !$installClickFraud);
            $this->send_json_response(200, 'Click fraud settings updated');
        } else {
            $this->send_json_response(403, 'Unauthorized access or security check failed');
        }

        wp_die();
    }

    public function update_whitelist()
    {
        if ($this->has_permission('update_whitelist') && isset($_POST['whitelist'])) {
            $whitelist = array_map('sanitize_text_field', explode(',', $_POST['whitelist']));
            $validatedIPs = array_filter($whitelist, [$this, 'validateIP']);

            if (count($validatedIPs) <= CC_MAX_IPS) {
                update_option('clickcease_whitelist', $validatedIPs);
                $this->send_json_response(200, 'Whitelist updated');
            } else {
                $this->send_json_response(400, 'Max allowed entries is 5');
            }
        } else {
            $this->send_json_response(403, 'Unauthorized access or security check failed');
        }

        wp_die();
    }

    private function validateIP($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }

    private function send_json_response($status, $data = null)
    {
        if ($status == 200) {
            wp_send_json_success($data);
        } else {
            wp_send_json_error($data);
        }
    }

    private function has_permission($action_name)
    {
        return isset($_POST['nonce']) && wp_verify_nonce($_POST['nonce'], $action_name) && current_user_can('manage_options');
    }
}

new WP_Rest_Route();

require_once clickcease_plugin_PLUGIN_PATH . '/classes/formService.php';
