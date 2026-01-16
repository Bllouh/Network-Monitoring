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

