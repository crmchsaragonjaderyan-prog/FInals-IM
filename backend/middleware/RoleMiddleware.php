<?php

declare(strict_types=1);

/**
 * Role Middleware
 * IT Laboratory Asset Tracking System
 *
 * This file only contains authorization helper functions.
 * It does NOT load bootstrap.php.
 */

if (!function_exists('require_login')) {

    function require_login(Auth $auth): void
    {
        if (!$auth->check()) {
            header('Location: index.php?page=login');
            exit;
        }
    }
}

if (!function_exists('require_role')) {

    function require_role(Auth $auth, array $allowedRoles): void
    {
        require_login($auth);

        $role = $auth->role();

        if (!in_array($role, $allowedRoles, true)) {
            http_response_code(403);

            echo '<!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Access Denied</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: #f5f6fa;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        margin: 0;
                    }

                    .error-box {
                        background: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 5px 20px rgba(0,0,0,.10);
                        text-align: center;
                        max-width: 450px;
                    }

                    h1 {
                        margin-bottom: 10px;
                    }

                    p {
                        color: #666;
                    }

                    a {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 10px 18px;
                        background: #2563eb;
                        color: white;
                        text-decoration: none;
                        border-radius: 6px;
                    }
                </style>
            </head>
            <body>

                <div class="error-box">
                    <h1>403 - Access Denied</h1>
                    <p>You do not have permission to access this page.</p>
                    <a href="index.php?page=dashboard">Return to Dashboard</a>
                </div>

            </body>
            </html>';

            exit;
        }
    }
}