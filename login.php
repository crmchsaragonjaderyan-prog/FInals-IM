<?php
declare(strict_types=1);

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/classes/Helpers.php';

if ($auth->check()) {
    header('Location: index.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Please enter your email and password.';
    } else {

        if ($auth->login($email, $password)) {
            header('Location: index.php');
            exit;
        }

        $error = 'Invalid email/password or unsupported role.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login | IT Laboratory Asset Tracking System</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f7fb;
        }

        .login-wrapper {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .login-card {
            width: 100%;
            max-width: 950px;
            min-height: 560px;
            background: #ffffff;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 10px 35px rgba(0, 0, 0, 0.12);
            display: flex;
        }

        .login-left {
            width: 48%;
            padding: 55px 45px;
            background: #0d6efd;
            color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .system-icon {
            width: 80px;
            height: 80px;
            border-radius: 18px;
            background: rgba(255, 255, 255, 0.18);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 38px;
            margin-bottom: 25px;
        }

        .login-left h1 {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 15px;
        }

        .login-left p {
            font-size: 16px;
            line-height: 1.7;
            opacity: 0.92;
        }

        .feature-list {
            margin-top: 25px;
            padding: 0;
            list-style: none;
        }

        .feature-list li {
            margin-bottom: 13px;
            font-size: 15px;
        }

        .feature-list li::before {
            content: "✓";
            font-weight: bold;
            margin-right: 10px;
        }

        .login-right {
            width: 52%;
            padding: 55px 50px;
            display: flex;
            align-items: center;
        }

        .login-form {
            width: 100%;
            max-width: 430px;
            margin: auto;
        }

        .login-form h2 {
            font-weight: 700;
            color: #212529;
            margin-bottom: 8px;
        }

        .login-subtitle {
            color: #6c757d;
            margin-bottom: 30px;
        }

        .form-label {
            font-weight: 600;
            color: #343a40;
        }

        .form-control {
            height: 50px;
            border-radius: 10px;
            padding: 10px 15px;
        }

        .form-control:focus {
            box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.15);
        }

        .password-wrapper {
            position: relative;
        }

        .password-wrapper .form-control {
            padding-right: 50px;
        }

        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            border: none;
            background: transparent;
            color: #6c757d;
            cursor: pointer;
            font-size: 18px;
        }

        .login-button {
            width: 100%;
            height: 50px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 16px;
            margin-top: 10px;
        }

        .demo-box {
            margin-top: 25px;
            padding: 15px;
            border-radius: 10px;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            font-size: 13px;
        }

        .demo-box strong {
            color: #212529;
        }

        .footer-text {
            margin-top: 25px;
            text-align: center;
            color: #6c757d;
            font-size: 13px;
        }

        @media (max-width: 768px) {

            .login-card {
                flex-direction: column;
                min-height: auto;
            }

            .login-left,
            .login-right {
                width: 100%;
            }

            .login-left {
                padding: 35px 30px;
            }

            .login-left h1 {
                font-size: 26px;
            }

            .feature-list {
                margin-bottom: 0;
            }

            .login-right {
                padding: 40px 30px;
            }
        }
    </style>
</head>

<body>

<div class="login-wrapper">

    <div class="login-card">

        <!-- LEFT SIDE -->
        <div class="login-left">

            <div class="system-icon">
                💻
            </div>

            <h1>
                IT Laboratory<br>
                Asset Tracking System
            </h1>

            <p>
                A centralized system for managing IT laboratory
                equipment, borrowers, loans, returns, inventory,
                notifications, and activity records.
            </p>

            <ul class="feature-list">
                <li>Hardware Inventory Management</li>
                <li>Equipment Borrowing and Returns</li>
                <li>Borrower Management</li>
                <li>Reports and Inventory Export</li>
                <li>Role-Based Access Control</li>
            </ul>

        </div>


        <!-- RIGHT SIDE -->
        <div class="login-right">

            <div class="login-form">

                <h2>Welcome Back</h2>

                <p class="login-subtitle">
                    Sign in to access the laboratory asset system.
                </p>


                <?php if ($error !== ''): ?>

                    <div
                        class="alert alert-danger alert-dismissible fade show"
                        role="alert"
                    >
                        <?= e($error) ?>

                        <button
                            type="button"
                            class="btn-close"
                            data-bs-dismiss="alert"
                            aria-label="Close"
                        ></button>
                    </div>

                <?php endif; ?>


                <form method="POST" action="">

                    <div class="mb-3">

                        <label
                            for="email"
                            class="form-label"
                        >
                            Email Address
                        </label>

                        <input
                            type="email"
                            class="form-control"
                            id="email"
                            name="email"
                            placeholder="Enter your email"
                            value="<?= e($_POST['email'] ?? '') ?>"
                            autocomplete="email"
                            required
                        >

                    </div>


                    <div class="mb-3">

                        <label
                            for="password"
                            class="form-label"
                        >
                            Password
                        </label>

                        <div class="password-wrapper">

                            <input
                                type="password"
                                class="form-control"
                                id="password"
                                name="password"
                                placeholder="Enter your password"
                                autocomplete="current-password"
                                required
                            >

                            <button
                                type="button"
                                class="toggle-password"
                                onclick="togglePassword()"
                                aria-label="Show password"
                            >
                                👁
                            </button>

                        </div>

                    </div>


                    <button
                        type="submit"
                        class="btn btn-primary login-button"
                    >
                        Sign In
                    </button>

                </form>


                <div class="demo-box">

                    <strong>Demo Accounts</strong>

                    <hr class="my-2">

                    <div>
                        <strong>Laboratory Staff:</strong><br>
                        admin@itlab.com / password
                    </div>

                    <div class="mt-2">
                        <strong>Student Assistant:</strong><br>
                        assistant@itlab.com / password
                    </div>

                    <div class="mt-2">
                        <strong>IT Instructor:</strong><br>
                        instructor@itlab.com / password
                    </div>

                </div>


                <div class="footer-text">
                    IT Laboratory Asset Tracking System
                    <br>
                    &copy; <?= date('Y') ?>
                </div>

            </div>

        </div>

    </div>

</div>


<script
    src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js">
</script>

<script>

function togglePassword() {

    const password =
        document.getElementById('password');

    const button =
        document.querySelector('.toggle-password');

    if (password.type === 'password') {

        password.type = 'text';
        button.textContent = '🙈';

    } else {

        password.type = 'password';
        button.textContent = '👁';

    }
}

</script>

</body>
</html>