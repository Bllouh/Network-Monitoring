<?php
session_start();
include '../inc/functions.php';

getAllConnectedDevices();
// Récupérer les appareils réellement connectés
$connectedDevices = getCurrentConnectedDevices();

// Initialiser les données des appareils si elles n'existent pas ou forcer la mise à jour
$devices = [];
$deviceId = 1;

foreach($connectedDevices as $device) {
    // Vérifier si l'appareil existe déjà dans la session (pour garder son statut)
    $existingDevice = null;
    if (isset($_SESSION['devices'])) {
        foreach ($_SESSION['devices'] as $sessionDevice) {
            if ($sessionDevice['mac'] === $device['mac']) {
                $existingDevice = $sessionDevice;
                break;
            }
        }
    }
    
    // Si l'appareil existe, garder ses paramètres, sinon créer un nouveau
    if ($existingDevice) {
        $devices[] = $existingDevice;
    } else {
        $devices[] = [
            'id' => $deviceId++,
            'name' => 'Appareil ' . $device['ip'], // Nom par défaut basé sur l'IP
            'ip' => $device['ip'],
            'mac' => $device['mac'],
            'status' => 'connected',
            'speedLimit' => null
        ];
    }
}

$_SESSION['devices'] = $devices;

// Initialiser les logs si ils n'existent pas
if (!isset($_SESSION['logs'])) {
    $_SESSION['logs'] = [
        ['time' => date('H:i'), 'icon' => 'fa-wifi', 'class' => 'log-info', 'message' => 'Scan du réseau terminé - ' . count($devices) . ' appareils détectés', 'type' => 'info']
    ];
}

// Traiter les actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $deviceId = isset($_POST['device_id']) ? (int)$_POST['device_id'] : 0;
    
    foreach ($_SESSION['devices'] as &$device) {
        if ($device['id'] === $deviceId) {
            $time = date('H:i');
            
            switch ($action) {
                case 'allow':
                    $device['status'] = 'connected';
                    $device['speedLimit'] = null;
                    array_unshift($_SESSION['logs'], [
                        'time' => $time,
                        'icon' => 'fa-check',
                        'class' => 'log-success',
                        'message' => "Appareil '{$device['name']}' ({$device['ip']}) autorisé",
                        'type' => 'success'
                    ]);
                    break;
                    
                case 'block':
                    $device['status'] = 'blocked';
                    $device['speedLimit'] = null;
                    array_unshift($_SESSION['logs'], [
                        'time' => $time,
                        'icon' => 'fa-ban',
                        'class' => 'log-danger',
                        'message' => "Appareil '{$device['name']}' ({$device['ip']}) bloqué",
                        'type' => 'danger'
                    ]);
                    break;
                    
                case 'limit':
                    $speedLimit = isset($_POST['speed_limit']) ? (int)$_POST['speed_limit'] : 10;
                    $device['status'] = 'limited';
                    $device['speedLimit'] = $speedLimit;
                    array_unshift($_SESSION['logs'], [
                        'time' => $time,
                        'icon' => 'fa-tachometer-alt',
                        'class' => 'log-warning',
                        'message' => "Limitation appliquée à '{$device['name']}' ({$device['ip']}) - {$speedLimit} Mbps",
                        'type' => 'warning'
                    ]);
                    break;
                    
                case 'remove_limit':
                    $device['status'] = 'connected';
                    $device['speedLimit'] = null;
                    array_unshift($_SESSION['logs'], [
                        'time' => $time,
                        'icon' => 'fa-unlock',
                        'class' => 'log-success',
                        'message' => "Limitation levée pour '{$device['name']}' ({$device['ip']})",
                        'type' => 'success'
                    ]);
                    break;
            }
            break;
        }
    }
    
    // Limiter le nombre de logs
    if (count($_SESSION['logs']) > 20) {
        $_SESSION['logs'] = array_slice($_SESSION['logs'], 0, 20);
    }
    
    // Redirection pour éviter la resoumission du formulaire
    header('Location: ' . $_SERVER['PHP_SELF'] . '?section=' . ($_GET['section'] ?? 'view-devices'));
    exit;
}

// Action pour lever toutes les limitations
if (isset($_GET['remove_all_limits'])) {
    $count = 0;
    foreach ($_SESSION['devices'] as &$device) {
        if ($device['status'] === 'limited') {
            $device['status'] = 'connected';
            $device['speedLimit'] = null;
            $count++;
        }
    }
    
    if ($count > 0) {
        array_unshift($_SESSION['logs'], [
            'time' => date('H:i'),
            'icon' => 'fa-unlock-alt',
            'class' => 'log-success',
            'message' => "$count limitation(s) levée(s)",
            'type' => 'success'
        ]);
    }
    
    header('Location: ' . $_SERVER['PHP_SELF'] . '?section=remove-limits');
    exit;
}

// Action pour effacer les logs
if (isset($_GET['clear_logs'])) {
    $_SESSION['logs'] = [];
    array_unshift($_SESSION['logs'], [
        'time' => date('H:i'),
        'icon' => 'fa-trash',
        'class' => 'log-info',
        'message' => 'Journal effacé',
        'type' => 'info'
    ]);
    header('Location: ' . $_SERVER['PHP_SELF'] . '?section=view-logs');
    exit;
}

// Calculer les statistiques
$connectedCount = 0;
$limitedCount = 0;
$blockedCount = 0;

foreach ($_SESSION['devices'] as $device) {
    if ($device['status'] === 'connected') $connectedCount++;
    if ($device['status'] === 'limited') $limitedCount++;
    if ($device['status'] === 'blocked') $blockedCount++;
}

$totalDevices = count($_SESSION['devices']);
$currentSection = $_GET['section'] ?? 'view-devices';

// Fonction pour obtenir l'icône selon l'adresse MAC ou IP
function getDeviceIcon($mac) {
    // Tu peux personnaliser selon les préfixes MAC des constructeurs
    $prefix = strtoupper(substr($mac, 0, 8));
    
    // Quelques exemples de préfixes MAC connus
    if (in_array($prefix, ['00:50:56', '00:0C:29', '00:05:69'])) return 'fa-server'; // VMware
    if (in_array($prefix, ['08:00:27'])) return 'fa-server'; // VirtualBox
    if (in_array($prefix, ['B8:27:EB', 'DC:A6:32'])) return 'fa-microchip'; // Raspberry Pi
    
    return 'fa-desktop'; // Par défaut
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Monitor | Administration Réseau</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <i class="fas fa-network-wired"></i>
                <h1>Network Monitor</h1>
            </div>
            <div class="status-indicator">
                <div class="status-dot"></div>
                <span>Système actif - <?php echo $totalDevices; ?> appareils connectés</span>
            </div>
        </header>

        <nav class="nav-container">
            <ul class="nav-menu">
                <li class="nav-item">
                    <a href="?section=view-devices" class="nav-link <?php echo $currentSection === 'view-devices' ? 'active' : ''; ?>">
                        <div class="nav-icon">
                            <i class="fas fa-eye"></i>
                        </div>
                        <div>
                            <div class="nav-text">Voir les PC connectés</div>
                            <div class="nav-description">Affiche tous les appareils sur le réseau</div>
                        </div>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="?section=view-logs" class="nav-link <?php echo $currentSection === 'view-logs' ? 'active' : ''; ?>">
                        <div class="nav-icon">
                            <i class="fas fa-clipboard-list"></i>
                        </div>
                        <div>
                            <div class="nav-text">Voir les logs</div>
                            <div class="nav-description">Historique des activités</div>
                        </div>
                    </a>
                </li>
            </ul>
        </nav>

        <!-- View Devices Section -->
        <section id="view-devices" class="content-section <?php echo $currentSection === 'view-devices' ? 'active' : ''; ?>">
            <div class="dashboard">
                <div class="main-content">
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value"><?php echo $totalDevices; ?></div>
                            <div class="stat-label">Appareils connectés</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?php echo $limitedCount; ?></div>
                            <div class="stat-label">Appareils limités</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?php echo $blockedCount; ?></div>
                            <div class="stat-label">Appareils bloqués</div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <h2><i class="fas fa-desktop"></i> Appareils connectés</h2>
                            <a href="?section=view-devices" class="btn btn-outline">
                                <i class="fas fa-sync-alt"></i> Actualiser
                            </a>
                        </div>
                        <div class="card-body">
                            <table class="devices-table">
                                <thead>
                                    <tr>
                                        <th>Appareil</th>
                                        <th>Adresse IP</th>
                                        <th>MAC</th>
                                        <th>Statut</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (count($_SESSION['devices']) > 0): ?>
                                        <?php foreach ($_SESSION['devices'] as $device): ?>
                                        <tr class="device-row">
                                            <td>
                                                <div class="device-info">
                                                    <div class="device-icon">
                                                        <i class="fas <?php echo getDeviceIcon($device['mac']); ?>"></i>
                                                    </div>
                                                    <div>
                                                        <div class="device-name"><?php echo htmlspecialchars($device['name']); ?></div>
                                                        <div class="device-mac"><?php echo htmlspecialchars($device['mac']); ?></div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td><?php echo htmlspecialchars($device['ip']); ?></td>
                                            <td><?php echo htmlspecialchars($device['mac']); ?></td>
                                            <td>
                                                <?php
                                                if ($device['status'] === 'connected') {
                                                    echo '<span class="device-status status-connected">Connecté</span>';
                                                } elseif ($device['status'] === 'blocked') {
                                                    echo '<span class="device-status status-blocked">Bloqué</span>';
                                                } elseif ($device['status'] === 'limited') {
                                                    echo '<span class="device-status status-limited">Limité (' . $device['speedLimit'] . ' Mbps)</span>';
                                                }
                                                ?>
                                            </td>
                                            <td>
                                                <div class="actions-cell">
                                                    <?php if ($device['status'] === 'connected'): ?>
                                                        <form method="POST" style="display:inline;">
                                                            <input type="hidden" name="action" value="block">
                                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                            <button type="submit" class="btn btn-danger btn-sm">
                                                                <i class="fas fa-ban"></i> Bloquer
                                                            </button>
                                                        </form>
                                                        <a href="?section=limit-bandwidth&device_id=<?php echo $device['id']; ?>" class="btn btn-warning btn-sm">
                                                            <i class="fas fa-tachometer-alt"></i> Limiter
                                                        </a>
                                                    <?php elseif ($device['status'] === 'blocked'): ?>
                                                        <form method="POST" style="display:inline;">
                                                            <input type="hidden" name="action" value="allow">
                                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                            <button type="submit" class="btn btn-success btn-sm">
                                                                <i class="fas fa-check"></i> Autoriser
                                                            </button>
                                                        </form>
                                                    <?php elseif ($device['status'] === 'limited'): ?>
                                                        <form method="POST" style="display:inline;">
                                                            <input type="hidden" name="action" value="block">
                                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                            <button type="submit" class="btn btn-danger btn-sm">
                                                                <i class="fas fa-ban"></i> Bloquer
                                                            </button>
                                                        </form>
                                                        <form method="POST" style="display:inline;">
                                                            <input type="hidden" name="action" value="remove_limit">
                                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                            <button type="submit" class="btn btn-success btn-sm">
                                                                <i class="fas fa-unlock"></i> Lever limite
                                                            </button>
                                                        </form>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <tr>
                                            <td colspan="5" style="text-align: center; padding: 20px;">
                                                <i class="fas fa-exclamation-circle"></i> Aucun appareil détecté sur le réseau
                                            </td>
                                        </tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="sidebar">
                    <div class="info-box">
                        <h3><i class="fas fa-info-circle"></i> Vue d'ensemble</h3>
                        <p>Cette section affiche tous les appareils actuellement connectés à votre réseau. Les données sont récupérées en temps réel via la commande <code>ip neigh</code>.</p>
                        <p><strong>Appareils détectés :</strong> <?php echo $totalDevices; ?></p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Le reste de ton code pour les autres sections... -->
    </div>
</body>
</html>