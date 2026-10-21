```php
<?php

declare(strict_types=1);

class Database
{
    private static ?Database $instance = null;

    private PDO $pdo;

    private function __construct()
    {
        $dsn = "mysql:host=" .'sql104.byetcluster.com';
             . ";port=3306;dbname=" if0_43162353_it_lab_asset_tracking
             . ";charset=utf8mb4";

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        $this->pdo = new PDO(
            $dsn,
            DB_USER,
            DB_PASS,
            $options
        );
    }

    public static function getInstance(): Database
    {
        if (self::$instance === null) {
            self::$instance = new Database();
        }

        return self::$instance;
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }
}
