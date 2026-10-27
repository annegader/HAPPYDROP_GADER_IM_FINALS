<?php
declare(strict_types=1);

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $location): never
{
    header('Location: ' . $location);
    exit;
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(): void
{
    $token = $_POST['csrf_token'] ?? '';
    if (!is_string($token) || !hash_equals(csrfToken(), $token)) {
        http_response_code(419);
        exit('Your session expired. Go back, refresh the page, and try again.');
    }
}

function requireLogin(): void
{
    if (empty($_SESSION['user_id'])) {
        redirect('?page=role');
    }
}

function requireAdmin(): void
{
    requireLogin();
    if (($_SESSION['user_role'] ?? '') !== 'admin') {
        http_response_code(403);
        exit('You do not have permission to access this page.');
    }
}

function setFlash(string $message, string $type = 'success'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

function userPlant(PDO $pdo, int $plantId, int $userId): ?array
{
    $statement = $pdo->prepare(
        'SELECT plant_id, common_name, watering_frequency_days
         FROM plants WHERE plant_id = :plant_id AND user_id = :user_id'
    );
    $statement->execute(['plant_id' => $plantId, 'user_id' => $userId]);
    $plant = $statement->fetch();

    return $plant ?: null;
}
