<?php

function ensureUtf8($data)
{
    if (is_string($data)) {
        return mb_convert_encoding($data, 'UTF-8', 'UTF-8');
    } elseif (is_array($data)) {
        foreach ($data as $key => $value) {
            $data[$key] = ensureUtf8($value);
        }
    }
    return $data;
}

function parseWireguardConfig($config, $number)
{
    $parsed = [];

    $parsed['type'] = 'wireguard';

    // Extract the main components
    $parts = parse_url($config);

    // Extract private key from the user info
    $parsed['private_key'] = urldecode($parts['user']);

    $parsed['server'] = $parts['host'];
    $parsed['server_port'] = $parts['port'];

    // Parse query string
    parse_str($parts['query'], $query);

    // Extract local addresses
    $addresses = explode(',', $query['address']);
    $parsed['local_address'] = $addresses;

    $parsed['peer_public_key'] = $query['publickey'];

    // Extract reserved
    $parsed['reserved'] = isset($query['reserved']) ? array_map('intval', explode(',', $query['reserved'])) : null;

    $parsed['mtu'] = isset($query['mtu']) ? intval($query['mtu']) : null;

    // Extract tag from fragment
    $parsed['tag'] = isset($parts['fragment']) ? $parts['fragment'] : null;
    $parsed['tag'] = $parsed['tag'] . "|Type $number";

    // Calculate fake packet values based on input number
    $parsed['fake_packets'] = ($number * 2 + 1) . '-' . ($number * 2 + 3);
    $parsed['fake_packets_size'] = ($number * 10 + 1) . '-' . ($number * 10 + 10);
    $parsed['fake_packets_delay'] = ($number * 20 + 1) . '-' . ($number * 20 + 10);

    return ensureUtf8($parsed);
}

// Read and parse the WireGuard configs
$wireguard_input = file_get_contents('config_wireguard.txt');
$wireguard_configs = explode("\n", trim($wireguard_input));

$new_outbounds = [];

foreach ($wireguard_configs as $config) {
    for ($number = 0; $number < 1; $number++) {
        $new_outbounds[] = parseWireguardConfig($config, $number);
    }
}

// Read and parse the structure
$json_input = file_get_contents('structure.json');
$json_config = json_decode($json_input, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die("Error parsing JSON config: " . json_last_error_msg() . "\n");
}

$json_config = ensureUtf8($json_config);

// Merge the new WireGuard outbounds with existing outbounds
$existing_outbounds = $json_config['outbounds'] ?? [];
$merged_outbounds = array_merge($existing_outbounds, $new_outbounds);

// Update the outbounds in the JSON config
$json_config['outbounds'] = $merged_outbounds;

// Update or create the selector and auto outbounds
$outbound_types = ['proxy', 'URL-TEST'];
foreach ($outbound_types as $outbound_type) {
    $outbound_index = array_search($outbound_type, array_column($json_config['outbounds'], 'tag'));

    if ($outbound_index === false) {
        // If the outbound doesn't exist, create it
        $new_outbound = [
            'type' => $outbound_type,
            'tag' => $outbound_type,
            'outbounds' => []
        ];
        if ($outbound_type === 'auto') {
            $new_outbound['url'] = 'http://cp.cloudflare.com/';
            $new_outbound['interval'] = '10m0s';
        }
        $json_config['outbounds'][] = $new_outbound;
        $outbound_index = count($json_config['outbounds']) - 1;
    }

    // Add new WireGuard outbounds to the selector/auto outbound
    foreach ($new_outbounds as $new_outbound) {
        if (!in_array($new_outbound['tag'], $json_config['outbounds'][$outbound_index]['outbounds'])) {
            $json_config['outbounds'][$outbound_index]['outbounds'][] = $new_outbound['tag'];
        }
    }
}

// Convert the updated config back to JSON
$json_output = json_encode($json_config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

if ($json_output === false) {
    die("Error encoding JSON: " . json_last_error_msg() . "\n");
}

// Save the updated JSON config
if (file_put_contents('subscriptions/singbox/wireguard.json', $json_output) === false) {
    die("Error writing to file\n");
}

echo "Conversion and merging complete. Output saved to updated_config.json\n";
