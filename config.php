<?php
declare(strict_types=1);

$dbHost = getenv('DB_HOST') ?: 'sql201.infinityfree.com';
$dbName = getenv('DB_NAME') ?: 'if0_43163247_plant_watering_system';
$dbUser = getenv('DB_USER') ?: 'if0_43163247';
$dbPassword = getenv('DB_PASSWORD') ?: 'ITSHAPPYDROP';
const ADMIN_SECRET_CODE = 'HAPPYDROPADMIN';

try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPassword,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $exception) {
    http_response_code(500);
    error_log('Plant Watering Reminder database connection error: ' . $exception->getMessage());
    exit('Unable to connect to the database. Import database.sql and check DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD.');
}

$requiredTables = [
    'users',
    'plant_categories',
    'plants',
    'watering_schedules',
    'watering_history',
    'notifications',
];
$tableStatement = $pdo->prepare(
    'SELECT table_name FROM information_schema.tables
     WHERE table_schema = DATABASE() AND table_name IN (?, ?, ?, ?, ?, ?)'
);
$tableStatement->execute($requiredTables);
$availableTables = $tableStatement->fetchAll(PDO::FETCH_COLUMN);
$missingTables = array_values(array_diff($requiredTables, $availableTables));

if ($missingTables !== []) {
    http_response_code(503);
    error_log('Plant Watering Reminder database schema is missing tables: ' . implode(', ', $missingTables));
    exit(
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>HappyDrop database setup required</title><body style="font-family:system-ui,sans-serif;max-width:680px;margin:12vh auto;padding:24px;color:#44253a">'
        . '<h1>HappyDrop database setup required</h1>'
        . '<p>The configured database is missing required application tables. Import <code>database.sql</code> into the configured database, then reload this page.</p>'
        . '<p>Database: <code>' . htmlspecialchars($dbName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code></p>'
        . '<p>Missing tables: <code>' . htmlspecialchars(implode(', ', $missingTables), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code></p>'
        . '<p>In phpMyAdmin, select the configured database, choose <strong>Import</strong>, and select this project\'s <code>database.sql</code>.</p>'
        . '</body></html>'
    );
}
