<?php

declare(strict_types=1);

class User
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Get all users.
     */
    public function all(): array
    {
        $stmt = $this->db->query("
            SELECT
                id,
                full_name,
                email,
                role,
                created_at
            FROM users
            ORDER BY full_name ASC
        ");

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Find a user by ID.
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare("
            SELECT
                id,
                full_name,
                email,
                role,
                created_at
            FROM users
            WHERE id = ?
            LIMIT 1
        ");

        $stmt->execute([$id]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        return $user ?: null;
    }

    /**
     * Find a user by email.
     */
    public function findByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare("
            SELECT *
            FROM users
            WHERE email = ?
            LIMIT 1
        ");

        $stmt->execute([$email]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        return $user ?: null;
    }

    /**
     * Create a new user.
     */
    public function create(
        string $fullName,
        string $email,
        string $password,
        string $role
    ): bool {
        $allowedRoles = [
            'staff',
            'student_assistant',
            'instructor'
        ];

        if (!in_array($role, $allowedRoles, true)) {
            return false;
        }

        $hashedPassword = password_hash(
            $password,
            PASSWORD_DEFAULT
        );

        $stmt = $this->db->prepare("
            INSERT INTO users
                (full_name, email, password, role)
            VALUES
                (?, ?, ?, ?)
        ");

        return $stmt->execute([
            $fullName,
            $email,
            $hashedPassword,
            $role
        ]);
    }

    /**
     * Update user information.
     */
    public function update(
        int $id,
        string $fullName,
        string $email,
        string $role
    ): bool {
        $allowedRoles = [
            'staff',
            'student_assistant',
            'instructor'
        ];

        if (!in_array($role, $allowedRoles, true)) {
            return false;
        }

        $stmt = $this->db->prepare("
            UPDATE users
            SET
                full_name = ?,
                email = ?,
                role = ?
            WHERE id = ?
        ");

        return $stmt->execute([
            $fullName,
            $email,
            $role,
            $id
        ]);
    }

    /**
     * Update password.
     */
    public function updatePassword(
        int $id,
        string $password
    ): bool {
        $hashedPassword = password_hash(
            $password,
            PASSWORD_DEFAULT
        );

        $stmt = $this->db->prepare("
            UPDATE users
            SET password = ?
            WHERE id = ?
        ");

        return $stmt->execute([
            $hashedPassword,
            $id
        ]);
    }

    /**
     * Delete a user.
     */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare("
            DELETE FROM users
            WHERE id = ?
        ");

        return $stmt->execute([$id]);
    }

    /**
     * Count users.
     */
    public function count(): int
    {
        $stmt = $this->db->query("
            SELECT COUNT(*)
            FROM users
        ");

        return (int) $stmt->fetchColumn();
    }
}