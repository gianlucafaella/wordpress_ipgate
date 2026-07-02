<?php
/**
 * Plugin Name: IP Gate (Cloudflare Aware)
 * Description: Limita l'accesso al sito in base all'IP pubblico reale (CF-Connecting-IP). Supporta IP singoli e CIDR (IPv4/IPv6). Include pagina impostazioni e bypass token.
 * Version: 1.0.0
 * Author: Gianluca Faella
 */

if (!defined('ABSPATH')) exit;

class IP_Gate_CF {
    const OPTION = 'ip_gate_cf_settings';
    const VERSION = '1.0.0';

    public function __construct() {
        // Run the gate very early, but after plugins are loaded
        add_action('plugins_loaded', [$this, 'maybe_gate'], 0);

        // Admin
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'settings_link']);

        // Default options on activation
        register_activation_hook(__FILE__, [$this, 'activate']);
    }

    public function activate() {
        $defaults = [
            'enabled' => 0,
            'mode' => 'allow', // allow | deny
            'ip_list' => "",
            'bypass_token' => '',
            'diagnostic_headers' => 1,
        ];
        $current = get_option(self::OPTION, []);
        update_option(self::OPTION, wp_parse_args($current, $defaults), false);
    }

    public function settings_link($links) {
        $links[] = '<a href="' . esc_url(admin_url('options-general.php?page=ip-gate-cf')) . '">'.esc_html__('Impostazioni', 'default').'</a>';
        return $links;
    }

    public function admin_menu() {
        add_options_page(
            'IP Gate',
            'IP Gate',
            'manage_options',
            'ip-gate-cf',
            [$this, 'render_settings_page']
        );
    }

    public function register_settings() {
        register_setting(self::OPTION, self::OPTION, [$this, 'sanitize_settings']);

        add_settings_section('ipgate_main', 'Impostazioni', '__return_false', 'ip-gate-cf');

        add_settings_field('enabled', 'Abilita protezione', [$this, 'field_enabled'], 'ip-gate-cf', 'ipgate_main');
        add_settings_field('mode', 'Modalità', [$this, 'field_mode'], 'ip-gate-cf', 'ipgate_main');
        add_settings_field('ip_list', 'IP/CIDR consentiti o bloccati', [$this, 'field_ip_list'], 'ip-gate-cf', 'ipgate_main');
        add_settings_field('bypass_token', 'Token di bypass (opzionale)', [$this, 'field_bypass'], 'ip-gate-cf', 'ipgate_main');
        add_settings_field('diagnostic_headers', 'Header diagnostici', [$this, 'field_diag'], 'ip-gate-cf', 'ipgate_main');
    }

    public function sanitize_settings($raw) {
        $out = [];

        $out['enabled'] = empty($raw['enabled']) ? 0 : 1;

        $mode = isset($raw['mode']) ? strtolower(trim($raw['mode'])) : 'allow';
        $out['mode'] = in_array($mode, ['allow', 'deny'], true) ? $mode : 'allow';

        $ip_list = isset($raw['ip_list']) ? (string)$raw['ip_list'] : '';
        // Normalize line endings
        $ip_list = str_replace(["\r\n", "\r"], "\n", $ip_list);
        // Allow anything here; we validate at runtime. Just trim excessive whitespace.
        $lines = array_map('trim', explode("\n", $ip_list));
        // Rebuild text area content neatly
        $out['ip_list'] = implode("\n", array_filter($lines, function($v){ return $v !== ''; }));

        $bypass = isset($raw['bypass_token']) ? trim((string)$raw['bypass_token']) : '';
        // Keep alphanum + - _ only
        $out['bypass_token'] = preg_replace('~[^a-zA-Z0-9_\-]~', '', $bypass);

        $out['diagnostic_headers'] = empty($raw['diagnostic_headers']) ? 0 : 1;

        return $out;
    }

    // === Admin fields ===

    public function field_enabled() {
        $o = get_option(self::OPTION);
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION); ?>[enabled]" value="1" <?php checked(!empty($o['enabled'])); ?>>
            Attiva il blocco IP sul front-end e back-end
        </label>
        <p class="description">Consiglio: configura prima IP e bypass, poi abilita.</p>
        <?php
    }

    public function field_mode() {
        $o = get_option(self::OPTION);
        $mode = isset($o['mode']) ? $o['mode'] : 'allow';
        ?>
        <select name="<?php echo esc_attr(self::OPTION); ?>[mode]">
            <option value="allow" <?php selected($mode, 'allow'); ?>>Allowlist — consenti solo gli IP elencati</option>
            <option value="deny"  <?php selected($mode, 'deny');  ?>>Denylist — blocca gli IP elencati</option>
        </select>
        <?php
    }

    public function field_ip_list() {
        $o = get_option(self::OPTION);
        $val = isset($o['ip_list']) ? $o['ip_list'] : '';
        ?>
        <textarea name="<?php echo esc_attr(self::OPTION); ?>[ip_list]" rows="8" cols="60" class="large-text code"
            placeholder="Esempi:
84.253.189.69
203.0.113.0/24
2001:db8::/32"><?php echo esc_textarea($val); ?></textarea>
        <p class="description">Uno per riga. Supportati IPv4, IPv6 e CIDR.</p>
        <?php
        $ipinfo = $this->detect_ip();
        ?>
        <p><strong>Il tuo IP visto dal server:</strong> <?php echo esc_html($ipinfo['ip'] ?: 'n/d'); ?> <code>(<?php echo esc_html($ipinfo['source']); ?>)</code></p>
        <?php
    }

    public function field_bypass() {
        $o = get_option(self::OPTION);
        $val = isset($o['bypass_token']) ? $o['bypass_token'] : '';
        ?>
        <input type="text" name="<?php echo esc_attr(self::OPTION); ?>[bypass_token]" value="<?php echo esc_attr($val); ?>" class="regular-text" placeholder="es. SAFE1234" maxlength="64">
        <p class="description">Se impostato, aggiungi <code>?ipgate=TOKEN</code> all’URL per bypassare temporaneamente il blocco (utile in caso di emergenza).</p>
        <?php
    }

    public function field_diag() {
        $o = get_option(self::OPTION);
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION); ?>[diagnostic_headers]" value="1" <?php checked(!empty($o['diagnostic_headers'])); ?>>
            Invia header diagnostici (<code>X-IP-Gate-Client</code>, <code>X-IP-Gate-From</code>)
        </label>
        <?php
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) return;
        ?>
        <div class="wrap">
            <h1>IP Gate</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields(self::OPTION);
                do_settings_sections('ip-gate-cf');
                submit_button();
                ?>
            </form>
            <hr>
            <h2>Note</h2>
            <ol>
                <li>Dietro Cloudflare, l’IP reale è in <code>CF-Connecting-IP</code>; <code>REMOTE_ADDR</code> sarà un IP Cloudflare.</li>
                <li>Se abiliti il blocco e vedi ancora le pagine, svuota la cache della CDN (es. Cloudflare) e l’OPcache di PHP.</li>
                <li>Per massima sicurezza, limita l’accesso all’origin a livello server (WAF/Firewall) alle sole IP range di Cloudflare.</li>
            </ol>
        </div>
        <?php
    }

    // === Gate logic ===

    public function maybe_gate() {
        // Don't gate CLI/CRON
        if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON)) {
            return;
        }

        $o = get_option(self::OPTION);
        if (empty($o['enabled'])) {
            return; // not active
        }

        // Bypass token (GET param ipgate=TOKEN)
        if (!empty($o['bypass_token'])) {
            $provided = isset($_GET['ipgate']) ? (string)$_GET['ipgate'] : '';
            if (hash_equals($o['bypass_token'], $provided)) {
                $this->maybe_send_diag_headers('bypass');
                return;
            }
        }

        $ipinfo = $this->detect_ip();
        $client_ip = $ipinfo['ip'];
        $source    = $ipinfo['source'];

        $this->maybe_send_diag_headers($source, $client_ip);

        // Invalid IP -> block
        if (!$client_ip || !filter_var($client_ip, FILTER_VALIDATE_IP)) {
            $this->send_forbidden('Richiesta non valida (IP non riconosciuto).', 'invalid');
        }

        $list = $this->parse_list(get_option(self::OPTION)['ip_list'] ?? '');
        $listed = $this->ip_in_list($client_ip, $list);

        $mode = isset($o['mode']) ? $o['mode'] : 'allow';
        $block = ($mode === 'allow' && !$listed) || ($mode === 'deny' && $listed);

        if ($block) {
            $this->send_forbidden('Accesso negato.', 'policy');
        }
    }

    private function detect_ip() : array {
        $ip = null;
        $source = 'none';

        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            $source = 'CF-Connecting-IP';
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Usual convention: first is the original client
            $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
            $ip = $parts[0] ?? null;
            $source = 'X-Forwarded-For(first)';
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = trim($_SERVER['REMOTE_ADDR']);
            $source = 'REMOTE_ADDR';
        }

        return ['ip' => $ip, 'source' => $source];
    }

    private function parse_list(string $raw) : array {
        $raw = str_replace(["\r\n", "\r"], "\n", $raw);
        $lines = array_map('trim', explode("\n", $raw));
        $lines = array_values(array_filter($lines, function($v){ return $v !== '' && strpos(ltrim($v), '#') !== 0; }));
        return $lines;
    }

    private function ip_in_list(string $ip, array $list) : bool {
        foreach ($list as $entry) {
            if ($this->ip_matches($ip, $entry)) return true;
        }
        return false;
    }

    private function ip_matches(string $ip, string $entry) : bool {
        $entry = trim($entry);
        if ($entry === '') return false;

        if (strpos($entry, '/') === false) {
            return strcasecmp($ip, $entry) === 0;
        }

        // CIDR
        [$subnet, $mask] = explode('/', $entry, 2);
        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) return false;
        if (strlen($ipBin) !== strlen($subnetBin)) return false;

        $mask = (int)$mask;
        $bytes = strlen($ipBin);
        $maxBits = $bytes * 8;
        if ($mask < 0 || $mask > $maxBits) return false;

        $fullBytes = intdiv($mask, 8);
        $remainder = $mask % 8;

        $maskBin = str_repeat("\xff", $fullBytes);
        if ($remainder) {
            $maskBin .= chr((0xff << (8 - $remainder)) & 0xff);
        }
        $maskBin = str_pad($maskBin, $bytes, "\0");

        return (($ipBin & $maskBin) === ($subnetBin & $maskBin));
    }

    private function maybe_send_diag_headers(string $source = 'none', string $ip = null) {
        $o = get_option(self::OPTION);
        if (empty($o['diagnostic_headers'])) return;
        if (!headers_sent()) {
            header('X-IP-Gate-Client: ' . ($ip ?? 'none'));
            header('X-IP-Gate-From: ' . $source);
        }
        error_log('[IP-GATE] source=' . $source . ' ip=' . ($ip ?? 'none') . ' uri=' . ($_SERVER['REQUEST_URI'] ?? ''));
    }

    private function send_forbidden(string $message, string $reason) {
        if (!headers_sent()) {
            if (function_exists('status_header')) status_header(403);
            else header('HTTP/1.1 403 Forbidden');

            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Content-Type: text/plain; charset=utf-8');
            header('X-IP-Gate-Decision: blocked (' . $reason . ')');
        }
        exit($message);
    }
}

new IP_Gate_CF();
