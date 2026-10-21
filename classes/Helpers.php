<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| IT Laboratory Asset Tracking System
| Helper Functions
|--------------------------------------------------------------------------
*/

/*
|--------------------------------------------------------------------------
| Role Labels
|--------------------------------------------------------------------------
*/

if (!defined('ROLE_LABELS')) {
    define('ROLE_LABELS', [
        'staff' => 'Staff',
        'student_assistant' => 'Student Assistant',
        'instructor' => 'Instructor',
    ]);
}

/*
|--------------------------------------------------------------------------
| Escape HTML
|--------------------------------------------------------------------------
*/

if (!function_exists('e')) {

    function e(mixed $value): string
    {
        return htmlspecialchars(
            (string) $value,
            ENT_QUOTES,
            'UTF-8'
        );
    }
}

/*
|--------------------------------------------------------------------------
| Redirect
|--------------------------------------------------------------------------
*/

if (!function_exists('redirect')) {

    function redirect(string $url): never
    {
        header('Location: ' . $url);
        exit;
    }
}

/*
|--------------------------------------------------------------------------
| Role Label
|--------------------------------------------------------------------------
*/

if (!function_exists('role_label')) {

    function role_label(?string $role): string
    {
        if ($role === null || $role === '') {
            return 'User';
        }

        return ROLE_LABELS[$role] ?? ucfirst(
            str_replace(
                '_',
                ' ',
                $role
            )
        );
    }
}

/*
|--------------------------------------------------------------------------
| Current User ID
|--------------------------------------------------------------------------
*/

if (!function_exists('current_user_id')) {

    function current_user_id(): ?int
    {
        if (
            isset($_SESSION['user_id']) &&
            is_numeric($_SESSION['user_id'])
        ) {
            return (int) $_SESSION['user_id'];
        }

        return null;
    }
}

/*
|--------------------------------------------------------------------------
| Current User Role
|--------------------------------------------------------------------------
*/

if (!function_exists('current_user_role')) {

    function current_user_role(): ?string
    {
        return isset($_SESSION['role'])
            ? (string) $_SESSION['role']
            : null;
    }
}

/*
|--------------------------------------------------------------------------
| CSRF Token
|--------------------------------------------------------------------------
*/

if (!function_exists('csrf_token')) {

    function csrf_token(): string
    {
        if (
            empty($_SESSION['csrf_token'])
        ) {
            $_SESSION['csrf_token'] =
                bin2hex(random_bytes(32));
        }

        return $_SESSION['csrf_token'];
    }
}

/*
|--------------------------------------------------------------------------
| Verify CSRF Token
|--------------------------------------------------------------------------
*/

if (!function_exists('verify_csrf_token')) {

    function verify_csrf_token(
        string $token
    ): bool {

        return isset($_SESSION['csrf_token'])
            && hash_equals(
                $_SESSION['csrf_token'],
                $token
            );
    }
}

/*
|--------------------------------------------------------------------------
| Format Date
|--------------------------------------------------------------------------
*/

if (!function_exists('format_date')) {

    function format_date(
        ?string $date,
        string $format = 'M d, Y'
    ): string {

        if (!$date) {
            return '—';
        }

        $timestamp = strtotime($date);

        if ($timestamp === false) {
            return '—';
        }

        return date(
            $format,
            $timestamp
        );
    }
}

/*
|--------------------------------------------------------------------------
| Format Date and Time
|--------------------------------------------------------------------------
*/

if (!function_exists('format_datetime')) {

    function format_datetime(
        ?string $datetime
    ): string {

        if (!$datetime) {
            return '—';
        }

        $timestamp = strtotime($datetime);

        if ($timestamp === false) {
            return '—';
        }

        return date(
            'M d, Y h:i A',
            $timestamp
        );
    }
}

/*
|--------------------------------------------------------------------------
| Status Label
|--------------------------------------------------------------------------
*/

if (!function_exists('status_label')) {

    function status_label(
        ?string $status
    ): string {

        if (!$status) {
            return '—';
        }

        return ucfirst(
            str_replace(
                '_',
                ' ',
                $status
            )
        );
    }
}

/*
|--------------------------------------------------------------------------
| Status CSS Class
|--------------------------------------------------------------------------
*/

if (!function_exists('status_class')) {

    function status_class(
        ?string $status
    ): string {

        return match ($status) {

            'available',
            'returned',
            'good',
            'read'
                => 'success',

            'borrowed',
            'pending',
            'fair'
                => 'warning',

            'overdue',
            'damaged',
            'unavailable'
                => 'danger',

            'maintenance'
                => 'info',

            default
                => 'secondary',
        };
    }
}