<?php
include 'connection.php';

function getAllConnectedDevices() {
    exec("ip neigh | awk '{print $1, $3 ,$5}'", $output);
    $DBO = dbconnect();

    foreach ($output as $line) {
        $parts = explode(" ", $line);
        if (count($parts) >= 2) {
            $ip = $parts[0];
            $interface = $parts[1];
            $mac = $parts[2];
            // Vérifier si le device existe déjà
            $stmt = $DBO->prepare("SELECT COUNT(*) FROM devices WHERE ip = ? AND mac = ?");
            $stmt->execute([$ip, $mac]);
            $count = $stmt->fetchColumn();

            if ($count == 0) {
                // Si n'existe pas, on insère
                $insert = $DBO->prepare("INSERT INTO devices (ip, mac, interface) VALUES (?, ?, ?)");
                $insert->execute([$ip, $mac, $interface]);
            }
        }
    }
}
function getCurrentConnectedDevices() {
    exec("iw dev wlan0 station dump | awk '/Station/ {print $2}'", $output);
    $DBO = dbconnect();
    $devices = [];

    foreach ($output as $mac) {
        // On cherche l'appareil par MAC
        $stmt = $DBO->prepare("SELECT ip, mac, nom FROM devices WHERE mac = ?");
        $stmt->execute([$mac]);
        $device = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($device) {
            // Si trouvé, on ajoute au tableau
            $devices[] = $device;
        } else {
            // Sinon, on peut ajouter juste le MAC si nécessaire
            $devices[] = [
                'ip' => null,
                'mac' => $mac,
                'nom' => null
            ];
        }
    }

    return $devices;
}

/**
 * Check if an IP address is already blocked
 */
function isIPBlocked($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException("Invalid IP address format: $ip");
    }
    
    $escapedIP = escapeshellarg($ip);
    $command = "sudo iptables -L INPUT -n | grep $escapedIP";
    
    exec($command, $output, $returnCode);
    
    // If grep finds the IP, return code is 0
    return $returnCode === 0;
}

/**
 * Block an IP address using iptables
 */
function blockConnectionForIP($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return [
            'success' => false,
            'error' => 'Invalid IP address format',
            'ip' => $ip
        ];
    }
    
    // Check if already blocked
    if (isIPBlocked($ip)) {
        return [
            'success' => false,
            'error' => 'IP address is already blocked',
            'ip' => $ip
        ];
    }
    
    $escapedIP = escapeshellarg($ip);
    $command = "sudo iptables -A INPUT -s $escapedIP -j DROP 2>&1";
    
    exec($command, $output, $returnCode);
    
    return [
        'success' => $returnCode === 0,
        'ip' => $ip,
        'output' => implode("\n", $output),
        'returnCode' => $returnCode,
        'message' => $returnCode === 0 ? "IP $ip successfully blocked" : "Failed to block IP $ip"
    ];
}

/**
 * Unblock an IP address using iptables
 */
function unblockConnectionForIP($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return [
            'success' => false,
            'error' => 'Invalid IP address format',
            'ip' => $ip
        ];
    }
    
    // Check if the IP is actually blocked
    if (!isIPBlocked($ip)) {
        return [
            'success' => false,
            'error' => 'IP address is not blocked',
            'ip' => $ip
        ];
    }
    
    $escapedIP = escapeshellarg($ip);
    $command = "sudo iptables -D INPUT -s $escapedIP -j DROP 2>&1";
    
    exec($command, $output, $returnCode);
    
    return [
        'success' => $returnCode === 0,
        'ip' => $ip,
        'output' => implode("\n", $output),
        'returnCode' => $returnCode,
        'message' => $returnCode === 0 ? "IP $ip successfully unblocked" : "Failed to unblock IP $ip"
    ];
}

/**
 * Get list of all blocked IP addresses
 */
function getBlockedIPs() {
    $command = "sudo iptables -L INPUT -n | grep DROP | awk '{print $4}' 2>&1";
    
    exec($command, $output, $returnCode);
    
    if ($returnCode !== 0) {
        return [
            'success' => false,
            'error' => 'Failed to retrieve blocked IPs',
            'ips' => []
        ];
    }
    
    // Filter out non-IP entries and remove /32 CIDR notation
    $ips = array_filter($output, function($line) {
        return filter_var(str_replace('/32', '', $line), FILTER_VALIDATE_IP);
    });
    
    $ips = array_map(function($ip) {
        return str_replace('/32', '', $ip);
    }, $ips);
    
    return [
        'success' => true,
        'ips' => array_values($ips),
        'count' => count($ips)
    ];
}

/**
 * Save iptables rules to make them persistent
 */
function saveIPTablesRules() {
    // For Debian/Ubuntu systems
    $command = "sudo sh -c 'iptables-save > /etc/iptables/rules.v4' 2>&1";
    
    exec($command, $output, $returnCode);
    
    return [
        'success' => $returnCode === 0,
        'output' => implode("\n", $output),
        'message' => $returnCode === 0 ? 'iptables rules saved successfully' : 'Failed to save iptables rules'
    ];
}

/**
 * Block multiple IP addresses at once
 */
function blockMultipleIPs(array $ips) {
    $results = [];
    
    foreach ($ips as $ip) {
        $results[$ip] = blockConnectionForIP($ip);
    }
    
    return $results;
}

/**
 * Unblock multiple IP addresses at once
 */
function unblockMultipleIPs(array $ips) {
    $results = [];
    
    foreach ($ips as $ip) {
        $results[$ip] = unblockConnectionForIP($ip);
    }
    
    return $results;
}

// Example usage:
/*
// Block an IP
$result = blockConnectionForIP('192.168.1.100');
print_r($result);

// Check if IP is blocked
$isBlocked = isIPBlocked('192.168.1.100');
echo "Is blocked: " . ($isBlocked ? 'Yes' : 'No') . "\n";

// Unblock an IP
$result = unblockConnectionForIP('192.168.1.100');
print_r($result);

// Get all blocked IPs
$blocked = getBlockedIPs();
print_r($blocked);

// Block multiple IPs
$results = blockMultipleIPs(['192.168.1.100', '10.0.0.50', '172.16.0.1']);
print_r($results);

// Save rules to persist across reboots
$saveResult = saveIPTablesRules();
print_r($saveResult);
*/

?>

