```php
<?php

declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

date_default_timezone_set('Asia/Manila');

/*
|--------------------------------------------------------------------------
| InfinityFree Database Settings
|--------------------------------------------------------------------------
*/

$host = 'sql104.byetcluster.com';
$db = 'if0_43162353_it_lab_asset_tracking';
$user = 'if0_43162353';
$pass = 'AX1fL2I6WU';
$charset = 'utf8mb4';

/*
|--------------------------------------------------------------------------
| Database Connection
|--------------------------------------------------------------------------
*/

try {
    $pdo = new PDO(
        "mysql:host=$host;port=3306;dbname=$db;charset=$charset",
        $user,
        $pass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch (PDOException $e) {
    error_log($e->getMessage());
    exit('Database connection failed. Please check the database configuration.');
}

/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/classes/Auth.php';

$auth = new Auth($pdo);
