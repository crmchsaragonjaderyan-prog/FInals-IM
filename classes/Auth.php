<?php

declare(strict_types=1);

class Auth
{
    private PDO $db;

    private const ROLES = [
        'staff',
        'student_assistant',
        'instructor'
    ];

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Login user
     */
    public function login(string $email, string $password): bool
    {
        $email = trim($email);

        $stmt = $this->db->prepare("
            SELECT *
            FROM users
            WHERE email = ?
            LIMIT 1
        ");

        $stmt->execute([$email]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return false;
        }

        /*
         * Normal password verification
         */
        $passwordValid = password_verify(
            $password,
            (string) $user['password']
        );

        /*
         * Temporary fallback for accounts whose password
         * was stored as plain text.
         */
        if (!$passwordValid && hash_equals((string) $user['password'], $password)) {
            $newHash = password_hash($password, PASSWORD_DEFAULT);

            $update = $this->db->prepare("
                UPDATE users
                SET password = ?
                WHERE id = ?
            ");

            $update->execute([
                $newHash,
                (int) $user['id']
            ]);

            $passwordValid = true;
        }

        if (!$passwordValid) {
            return false;
        }

        /*
         * Check allowed role
         */
        if (!in_array((string) $user['role'], self::ROLES, true)) {
            return false;
        }

        /*
         * Create secure session
         */
        session_regenerate_id(true);

        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['full_name'] = (string) $user['full_name'];
        $_SESSION['email'] = (string) $user['email'];
        $_SESSION['role'] = (string) $user['role'];
        $_SESSION['logged_in'] = true;

        return true;
    }

    /**
     * Logout
     */
    public function logout(): void
    {
        $_SESSION = [];

        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();

            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }

        session_destroy();
    }

    /**
     * Check if logged in
     */
    public function check(): bool
    {
        return isset($_SESSION['user_id'])
            && isset($_SESSION['logged_in'])
            && $_SESSION['logged_in'] === true;
    }

    /**
     * Get current user
     */
    public function user(): ?array
    {
        if (!$this->check()) {
            return null;
        }

        $stmt = $this->db->prepare("
            SELECT *
            FROM users
            WHERE id = ?
            LIMIT 1
        ");

        $stmt->execute([
            (int) $_SESSION['user_id']
        ]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        return $user ?: null;
    }

    /**
     * Get current user ID
     */
    public function id(): ?int
    {
        if (!$this->check()) {
            return null;
        }

        return (int) $_SESSION['user_id'];
    }

    /**
     * Get current user role
     */
    public function role(): ?string
    {
        if (!$this->check()) {
            return null;
        }

        return (string) $_SESSION['role'];
    }

    /**
     * Check exact role
     */
    public function hasRole(string $role): bool
    {
        return $this->check()
            && isset($_SESSION['role'])
            && $_SESSION['role'] === $role;
    }

    /**
     * Check multiple roles
     */
    public function hasAnyRole(array $roles): bool
    {
        return $this->check()
            && isset($_SESSION['role'])
            && in_array($_SESSION['role'], $roles, true);
    }

    /**
     * Permission system
     */
    public function can(string $permission): bool
    {
        if (!$this->check()) {
            return false;
        }

        $role = $this->role();

        $permissions = [

            'staff' => [
                'dashboard',
                'inventory',
                'inventory_view',
                'categories',
                'borrowers',
                'loans',
                'reports',
                'reports_self',
                'notifications',
                'audit',
                'users',
                'profile',
                'my_loans'
            ],

            'student_assistant' => [
                'dashboard',
                'inventory',
                'inventory_view',
                'borrowers',
                'loans',
                'notifications',
                'profile',
                'my_loans',
                'reports_self'
            ],

            'instructor' => [
                'dashboard',
                'inventory_view',
                'notifications',
                'profile',
                'my_loans',
                'reports_self'
            ]
        ];

        return isset($permissions[$role])
            && in_array($permission, $permissions[$role], true);
    }
}