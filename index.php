<?php
declare(strict_types=1);

session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Lax',
]);
session_start();
require __DIR__ . '/config.php';
require __DIR__ . '/functions.php';

$page = (string) ($_GET['page'] ?? 'login');
$publicPages = ['role', 'login', 'register'];
$isAuthenticated = !empty($_SESSION['user_id']);
if (!$isAuthenticated && empty($_SESSION['selected_role'])) {
    $_SESSION['selected_role'] = 'plant_owner';
}
$userRole = (string) ($_SESSION['user_role'] ?? '');
$isAdmin = $userRole === 'admin';
if ($isAuthenticated) {
    $sessionRole = $userRole;
    $accountStatement = $pdo->prepare('SELECT first_name, role FROM users WHERE user_id = :user_id');
    $accountStatement->execute(['user_id' => (int) $_SESSION['user_id']]);
    $account = $accountStatement->fetch();
    if (!$account) {
        $_SESSION = [];
        session_destroy();
        redirect('?page=login');
    }
    $_SESSION['user_name'] = $account['first_name'];
    $_SESSION['user_role'] = $account['role'];
    $userRole = $account['role'];
    $isAdmin = $userRole === 'admin';
    if ($sessionRole !== $userRole) {
        redirect($isAdmin ? '?page=admin' : '?page=dashboard');
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' && !$isAuthenticated && !in_array($page, $publicPages, true)) {
    redirect('?page=login');
}
if (!$isAuthenticated && in_array($page, ['login', 'register'], true) && empty($_SESSION['selected_role'])) {
    redirect('?page=login');
}
if (!$isAuthenticated && $page === 'register'
    && !in_array($_SESSION['selected_role'] ?? '', ['plant_owner', 'admin'], true)) {
    redirect('?page=login');
}
$adminAccountExists = false;
$adminSecretCode = ADMIN_SECRET_CODE;
if (!$isAuthenticated && ($_SESSION['selected_role'] ?? '') === 'admin') {
    $adminAccountStatement = $pdo->query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1");
    $adminAccountExists = (bool) $adminAccountStatement->fetch();
    if ($page === 'register' && $adminAccountExists) {
        setFlash('An administrator account already exists. Sign in with that account.', 'error');
        redirect('?page=login');
    }
}
if ($isAuthenticated && in_array($page, $publicPages, true)) {
    redirect($isAdmin ? '?page=admin' : '?page=dashboard');
}
if ($isAuthenticated) {
    $allowedPages = $isAdmin
        ? ['admin', 'statistics', 'notifications', 'settings', 'help', 'plant-form', 'schedules', 'schedule-form', 'profile']
        : ['dashboard', 'plants', 'plant-form', 'schedules', 'schedule-form', 'history', 'profile', 'statistics', 'notifications', 'settings', 'help'];
    if (!in_array($page, $allowedPages, true)) {
        http_response_code(403);
        exit('You do not have permission to access this page.');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrfToken();
    $action = (string) ($_POST['action'] ?? '');

    try {
        if ($action === 'select_role') {
            $selectedRole = (string) ($_POST['role'] ?? '');
            if (!in_array($selectedRole, ['admin', 'plant_owner'], true)) {
                throw new InvalidArgumentException('Choose a valid account role.');
            }
            $_SESSION['selected_role'] = $selectedRole;
            $nextPage = (string) ($_POST['next_page'] ?? 'login');
            if (!in_array($nextPage, ['login', 'register'], true)) {
                $nextPage = 'login';
            }
            if ($nextPage === 'register' && $selectedRole === 'admin' && $adminAccountExists) {
                setFlash('An administrator account already exists. Sign in with that account.', 'error');
                redirect('?page=login');
            }
            redirect('?page=' . $nextPage);
        }

        if ($action === 'register') {
            if (($_SESSION['selected_role'] ?? '') !== 'plant_owner') {
                throw new InvalidArgumentException('Only plant owners can create an account here.');
            }
            $firstName = trim((string) ($_POST['first_name'] ?? ''));
            $lastName = trim((string) ($_POST['last_name'] ?? ''));
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $password = (string) ($_POST['password'] ?? '');
            $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

            if ($firstName === '' || $lastName === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Enter your name and a valid email address.');
            }
            if (strlen($password) < 8) {
                throw new InvalidArgumentException('Password must be at least 8 characters.');
            }
            if ($password !== $confirmPassword) {
                throw new InvalidArgumentException('Passwords do not match.');
            }

            $statement = $pdo->prepare(
                'INSERT INTO users (first_name, last_name, email, password_hash, role)
                 VALUES (:first_name, :last_name, :email, :password_hash, :role)'
            );
            $statement->execute([
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $email,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'role' => 'plant_owner',
            ]);
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $pdo->lastInsertId();
            $_SESSION['user_name'] = $firstName;
            $_SESSION['user_role'] = 'plant_owner';
            unset($_SESSION['selected_role']);
            redirect('?page=dashboard');
        }

        if ($action === 'register_admin') {
            if (($_SESSION['selected_role'] ?? '') !== 'admin') {
                throw new InvalidArgumentException('Choose the Administrator role before creating an admin account.');
            }
            if ($adminAccountExists) {
                throw new InvalidArgumentException('An administrator account already exists. Sign in with that account.');
            }
            $submittedSecretCode = (string) ($_POST['admin_secret_code'] ?? '');
            if (!hash_equals($adminSecretCode, $submittedSecretCode)) {
                throw new InvalidArgumentException('The administrator secret code is incorrect.');
            }

            $firstName = trim((string) ($_POST['first_name'] ?? ''));
            $lastName = trim((string) ($_POST['last_name'] ?? ''));
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $password = (string) ($_POST['password'] ?? '');
            $confirmPassword = (string) ($_POST['confirm_password'] ?? '');
            if ($firstName === '' || $lastName === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Enter your name and a valid email address.');
            }
            if (strlen($password) < 8) {
                throw new InvalidArgumentException('Password must be at least 8 characters.');
            }
            if ($password !== $confirmPassword) {
                throw new InvalidArgumentException('Passwords do not match.');
            }

            $pdo->beginTransaction();
            $statement = $pdo->prepare(
                'INSERT INTO users (first_name, last_name, email, password_hash, role)
                 VALUES (:first_name, :last_name, :email, :password_hash, :role)'
            );
            $statement->execute([
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $email,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'role' => 'admin',
            ]);
            $adminUserId = (int) $pdo->lastInsertId();
            $pdo->commit();

            session_regenerate_id(true);
            $_SESSION['user_id'] = $adminUserId;
            $_SESSION['user_name'] = $firstName;
            $_SESSION['user_role'] = 'admin';
            unset($_SESSION['selected_role']);
            redirect('?page=admin');
        }

        if ($action === 'login') {
            $selectedRole = (string) ($_SESSION['selected_role'] ?? '');
            if (!in_array($selectedRole, ['admin', 'plant_owner'], true)) {
                throw new InvalidArgumentException('Choose your account role before signing in.');
            }
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $statement = $pdo->prepare(
                'SELECT user_id, first_name, password_hash, role FROM users WHERE email = :email'
            );
            $statement->execute(['email' => $email]);
            $user = $statement->fetch();
            if (!$user || !password_verify((string) ($_POST['password'] ?? ''), $user['password_hash'])
                || $user['role'] !== $selectedRole) {
                throw new InvalidArgumentException('The email or password is incorrect.');
            }
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $user['user_id'];
            $_SESSION['user_name'] = $user['first_name'];
            $_SESSION['user_role'] = $user['role'];
            unset($_SESSION['selected_role']);
            redirect($user['role'] === 'admin' ? '?page=admin' : '?page=dashboard');
        }

        if ($action === 'logout') {
            $_SESSION = [];
            session_destroy();
            redirect('?page=login');
        }

        requireLogin();
        $userId = (int) $_SESSION['user_id'];

        if (in_array($action, ['admin_delete_user', 'admin_set_user_role', 'admin_delete_plant', 'admin_delete_schedule'], true)) {
            requireAdmin();
            if ($action === 'admin_delete_user') {
                $targetUserId = filter_input(INPUT_POST, 'target_user_id', FILTER_VALIDATE_INT) ?: 0;
                if ($targetUserId < 1 || $targetUserId === $userId) {
                    throw new InvalidArgumentException('You cannot delete your own administrator account.');
                }
                $pdo->beginTransaction();
                $target = $pdo->prepare('SELECT role FROM users WHERE user_id = :user_id FOR UPDATE');
                $target->execute(['user_id' => $targetUserId]);
                $targetUser = $target->fetch();
                if (!$targetUser) {
                    $pdo->rollBack();
                    throw new InvalidArgumentException('User not found.');
                }
                if ($targetUser['role'] === 'admin') {
                    $admins = $pdo->query("SELECT user_id FROM users WHERE role = 'admin' FOR UPDATE")->fetchAll();
                    if (count($admins) <= 1) {
                        $pdo->rollBack();
                        throw new InvalidArgumentException('The last administrator account cannot be deleted.');
                    }
                }
                $delete = $pdo->prepare('DELETE FROM users WHERE user_id = :user_id');
                $delete->execute(['user_id' => $targetUserId]);
                $pdo->commit();
                setFlash('User account and related plant records deleted.');
                redirect('?page=admin');
            }
            if ($action === 'admin_set_user_role') {
                $targetUserId = filter_input(INPUT_POST, 'target_user_id', FILTER_VALIDATE_INT) ?: 0;
                $targetRole = (string) ($_POST['role'] ?? '');
                if ($targetUserId < 1 || $targetUserId === $userId
                    || !in_array($targetRole, ['admin', 'plant_owner'], true)) {
                    throw new InvalidArgumentException('Choose a valid user and role.');
                }
                $pdo->beginTransaction();
                $target = $pdo->prepare('SELECT role FROM users WHERE user_id = :user_id FOR UPDATE');
                $target->execute(['user_id' => $targetUserId]);
                $targetUser = $target->fetch();
                if (!$targetUser) {
                    $pdo->rollBack();
                    throw new InvalidArgumentException('User not found.');
                }
                if ($targetUser['role'] === 'admin' && $targetRole !== 'admin') {
                    $admins = $pdo->query("SELECT user_id FROM users WHERE role = 'admin' FOR UPDATE")->fetchAll();
                    if (count($admins) <= 1) {
                        $pdo->rollBack();
                        throw new InvalidArgumentException('The last administrator account cannot be demoted.');
                    }
                }
                if ($targetUser['role'] !== 'admin' && $targetRole === 'admin') {
                    $admins = $pdo->query("SELECT user_id FROM users WHERE role = 'admin' FOR UPDATE")->fetchAll();
                    if ($admins) {
                        $pdo->rollBack();
                        throw new InvalidArgumentException('Only one administrator account is allowed.');
                    }
                }
                $update = $pdo->prepare('UPDATE users SET role = :role WHERE user_id = :user_id');
                $update->execute(['role' => $targetRole, 'user_id' => $targetUserId]);
                $pdo->commit();
                setFlash('User role updated.');
                redirect('?page=admin');
            }
            if ($action === 'admin_delete_plant') {
                $plantId = filter_input(INPUT_POST, 'plant_id', FILTER_VALIDATE_INT) ?: 0;
                $delete = $pdo->prepare('DELETE FROM plants WHERE plant_id = :plant_id');
                $delete->execute(['plant_id' => $plantId]);
                if ($delete->rowCount() !== 1) {
                    throw new InvalidArgumentException('Plant not found.');
                }
                setFlash('Plant and its related watering records deleted.');
                redirect('?page=admin');
            }
            $scheduleId = filter_input(INPUT_POST, 'schedule_id', FILTER_VALIDATE_INT) ?: 0;
            $delete = $pdo->prepare('DELETE FROM watering_schedules WHERE schedule_id = :schedule_id');
            $delete->execute(['schedule_id' => $scheduleId]);
            if ($delete->rowCount() !== 1) {
                throw new InvalidArgumentException('Schedule not found.');
            }
            setFlash('Watering schedule deleted.');
            redirect('?page=admin');
        }

        if ($action === 'save_plant') {
            $plantId = filter_input(INPUT_POST, 'plant_id', FILTER_VALIDATE_INT) ?: 0;
            $ownerId = $isAdmin
                ? (filter_input(INPUT_POST, 'owner_id', FILTER_VALIDATE_INT) ?: 0)
                : $userId;
            $name = trim((string) ($_POST['common_name'] ?? ''));
            $scientificName = trim((string) ($_POST['scientific_name'] ?? ''));
            $categoryId = filter_input(INPUT_POST, 'category_id', FILTER_VALIDATE_INT) ?: null;
            $frequency = filter_input(INPUT_POST, 'watering_frequency_days', FILTER_VALIDATE_INT);
            $dateAdded = (string) ($_POST['date_added'] ?? date('Y-m-d'));
            $notes = trim((string) ($_POST['notes'] ?? ''));

            if ($name === '' || !$frequency || $frequency < 1 || $frequency > 365) {
                throw new InvalidArgumentException('Plant name and a watering interval from 1 to 365 days are required.');
            }
            if ($isAdmin) {
                $ownerCheck = $pdo->prepare("SELECT user_id FROM users WHERE user_id = :user_id AND role = 'plant_owner'");
                $ownerCheck->execute(['user_id' => $ownerId]);
                if (!$ownerCheck->fetch()) {
                    throw new InvalidArgumentException('Choose a valid plant owner.');
                }
            }
            $date = DateTime::createFromFormat('Y-m-d', $dateAdded);
            if (!$date || $date->format('Y-m-d') !== $dateAdded) {
                throw new InvalidArgumentException('Enter a valid date added.');
            }
            if ($categoryId !== null) {
                $categoryCheck = $pdo->prepare('SELECT category_id FROM plant_categories WHERE category_id = :id');
                $categoryCheck->execute(['id' => $categoryId]);
                if (!$categoryCheck->fetch()) {
                    throw new InvalidArgumentException('Choose a valid plant category.');
                }
            }

            if ($plantId > 0) {
                if ($isAdmin) {
                    $statement = $pdo->prepare(
                        'UPDATE plants SET user_id = :user_id, category_id = :category_id,
                         common_name = :common_name, scientific_name = :scientific_name,
                         watering_frequency_days = :frequency, date_added = :date_added, notes = :notes
                         WHERE plant_id = :plant_id'
                    );
                    $statement->execute([
                        'user_id' => $ownerId,
                        'category_id' => $categoryId,
                        'common_name' => $name,
                        'scientific_name' => $scientificName ?: null,
                        'frequency' => $frequency,
                        'date_added' => $dateAdded,
                        'notes' => $notes ?: null,
                        'plant_id' => $plantId,
                    ]);
                    $plantExists = $pdo->prepare('SELECT plant_id FROM plants WHERE plant_id = :plant_id');
                    $plantExists->execute(['plant_id' => $plantId]);
                    $exists = (bool) $plantExists->fetch();
                } else {
                    $statement = $pdo->prepare(
                        'UPDATE plants SET category_id = :category_id, common_name = :common_name,
                         scientific_name = :scientific_name, watering_frequency_days = :frequency,
                         date_added = :date_added, notes = :notes
                         WHERE plant_id = :plant_id AND user_id = :user_id'
                    );
                    $statement->execute([
                        'category_id' => $categoryId,
                        'common_name' => $name,
                        'scientific_name' => $scientificName ?: null,
                        'frequency' => $frequency,
                        'date_added' => $dateAdded,
                        'notes' => $notes ?: null,
                        'plant_id' => $plantId,
                        'user_id' => $userId,
                    ]);
                    $exists = $statement->rowCount() > 0 || (bool) userPlant($pdo, $plantId, $userId);
                }
                if (!$exists) {
                    throw new InvalidArgumentException('Plant not found.');
                }
                setFlash('Plant details updated.');
            } else {
                $pdo->beginTransaction();
                $statement = $pdo->prepare(
                    'INSERT INTO plants (user_id, category_id, common_name, scientific_name,
                     watering_frequency_days, date_added, notes)
                     VALUES (:user_id, :category_id, :common_name, :scientific_name,
                     :frequency, :date_added, :notes)'
                );
                $statement->execute([
                    'user_id' => $ownerId,
                    'category_id' => $categoryId,
                    'common_name' => $name,
                    'scientific_name' => $scientificName ?: null,
                    'frequency' => $frequency,
                    'date_added' => $dateAdded,
                    'notes' => $notes ?: null,
                ]);
                $newPlantId = (int) $pdo->lastInsertId();
                $schedule = $pdo->prepare(
                    'INSERT INTO watering_schedules (plant_id, next_watering_at, repeat_interval_days)
                     VALUES (:plant_id, :next_watering_at, :frequency)'
                );
                $schedule->execute([
                    'plant_id' => $newPlantId,
                    'next_watering_at' => date('Y-m-d 09:00:00', strtotime('+' . $frequency . ' days')),
                    'frequency' => $frequency,
                ]);
                $pdo->commit();
                setFlash('Plant added with a watering schedule.');
            }
            redirect($isAdmin ? '?page=admin' : '?page=dashboard');
        }

        if ($action === 'delete_plant') {
            $plantId = filter_input(INPUT_POST, 'plant_id', FILTER_VALIDATE_INT);
            $statement = $pdo->prepare('DELETE FROM plants WHERE plant_id = :plant_id AND user_id = :user_id');
            $statement->execute(['plant_id' => $plantId, 'user_id' => $userId]);
            if ($statement->rowCount() !== 1) {
                throw new InvalidArgumentException('Plant not found.');
            }
            setFlash('Plant and its related schedules and history were deleted.');
            redirect('?page=dashboard');
        }

        if ($action === 'save_schedule') {
            $plantId = filter_input(INPUT_POST, 'plant_id', FILTER_VALIDATE_INT);
            $scheduleId = filter_input(INPUT_POST, 'schedule_id', FILTER_VALIDATE_INT) ?: 0;
            $nextDate = (string) ($_POST['next_watering_at'] ?? '');
            $frequency = filter_input(INPUT_POST, 'repeat_interval_days', FILTER_VALIDATE_INT);
            if ($isAdmin && $plantId) {
                $plantStatement = $pdo->prepare(
                    'SELECT plant_id, common_name, watering_frequency_days FROM plants WHERE plant_id = :plant_id'
                );
                $plantStatement->execute(['plant_id' => $plantId]);
                $plant = $plantStatement->fetch() ?: null;
            } else {
                $plant = $plantId ? userPlant($pdo, $plantId, $userId) : null;
            }
            $date = DateTime::createFromFormat('Y-m-d\TH:i', $nextDate);
            if (!$plant || !$date || $date->format('Y-m-d\TH:i') !== $nextDate || !$frequency || $frequency < 1 || $frequency > 365) {
                throw new InvalidArgumentException('Choose a plant, a valid next watering date, and an interval from 1 to 365 days.');
            }

            if ($scheduleId > 0) {
                if ($isAdmin) {
                    $statement = $pdo->prepare(
                        'UPDATE watering_schedules SET next_watering_at = :next_watering_at,
                         repeat_interval_days = :frequency, active = 1
                         WHERE schedule_id = :schedule_id AND plant_id = :plant_id'
                    );
                    $statement->execute([
                        'next_watering_at' => $date->format('Y-m-d H:i:s'),
                        'frequency' => $frequency,
                        'schedule_id' => $scheduleId,
                        'plant_id' => $plantId,
                    ]);
                } else {
                    $statement = $pdo->prepare(
                        'UPDATE watering_schedules ws JOIN plants p ON p.plant_id = ws.plant_id
                         SET ws.next_watering_at = :next_watering_at,
                             ws.repeat_interval_days = :frequency, ws.active = 1
                         WHERE ws.schedule_id = :schedule_id AND ws.plant_id = :plant_id AND p.user_id = :user_id'
                    );
                    $statement->execute([
                        'next_watering_at' => $date->format('Y-m-d H:i:s'),
                        'frequency' => $frequency,
                        'schedule_id' => $scheduleId,
                        'plant_id' => $plantId,
                        'user_id' => $userId,
                    ]);
                }
                if ($statement->rowCount() === 0) {
                    if ($isAdmin) {
                        $check = $pdo->prepare(
                            'SELECT schedule_id FROM watering_schedules WHERE schedule_id = :schedule_id AND plant_id = :plant_id'
                        );
                        $check->execute(['schedule_id' => $scheduleId, 'plant_id' => $plantId]);
                    } else {
                        $check = $pdo->prepare(
                            'SELECT ws.schedule_id FROM watering_schedules ws
                             JOIN plants p ON p.plant_id = ws.plant_id
                             WHERE ws.schedule_id = :schedule_id AND ws.plant_id = :plant_id AND p.user_id = :user_id'
                        );
                        $check->execute([
                            'schedule_id' => $scheduleId,
                            'plant_id' => $plantId,
                            'user_id' => $userId,
                        ]);
                    }
                    if (!$check->fetch()) {
                        throw new InvalidArgumentException('Schedule not found.');
                    }
                }
            } else {
                $statement = $pdo->prepare(
                    'INSERT INTO watering_schedules (plant_id, next_watering_at, repeat_interval_days)
                     VALUES (:plant_id, :next_watering_at, :frequency)'
                );
                $statement->execute([
                    'plant_id' => $plantId,
                    'next_watering_at' => $date->format('Y-m-d H:i:s'),
                    'frequency' => $frequency,
                ]);
            }
            setFlash('Watering schedule saved.');
            redirect('?page=schedules');
        }

        if ($action === 'delete_schedule') {
            $scheduleId = filter_input(INPUT_POST, 'schedule_id', FILTER_VALIDATE_INT);
            if ($isAdmin) {
                $statement = $pdo->prepare('DELETE FROM watering_schedules WHERE schedule_id = :schedule_id');
                $statement->execute(['schedule_id' => $scheduleId]);
            } else {
                $statement = $pdo->prepare(
                    'DELETE ws FROM watering_schedules ws
                     JOIN plants p ON p.plant_id = ws.plant_id
                     WHERE ws.schedule_id = :schedule_id AND p.user_id = :user_id'
                );
                $statement->execute(['schedule_id' => $scheduleId, 'user_id' => $userId]);
            }
            if ($statement->rowCount() !== 1) {
                throw new InvalidArgumentException('Schedule not found.');
            }
            setFlash('Watering schedule deleted.');
            redirect($isAdmin ? '?page=admin' : '?page=schedules');
        }

        if ($action === 'water_plant') {
            $plantId = filter_input(INPUT_POST, 'plant_id', FILTER_VALIDATE_INT);
            $plant = $plantId ? userPlant($pdo, $plantId, $userId) : null;
            if (!$plant) {
                throw new InvalidArgumentException('Plant not found.');
            }
            $notes = trim((string) ($_POST['notes'] ?? ''));
            $pdo->beginTransaction();
            $history = $pdo->prepare(
                'INSERT INTO watering_history (plant_id, watered_at, notes)
                 VALUES (:plant_id, NOW(), :notes)'
            );
            $history->execute(['plant_id' => $plantId, 'notes' => $notes ?: null]);
            $schedule = $pdo->prepare(
                'SELECT schedule_id, repeat_interval_days FROM watering_schedules
                 WHERE plant_id = :plant_id AND active = 1 ORDER BY schedule_id DESC LIMIT 1'
            );
            $schedule->execute(['plant_id' => $plantId]);
            $activeSchedule = $schedule->fetch();
            if ($activeSchedule) {
                $interval = (int) $activeSchedule['repeat_interval_days'];
                $nextWateringAt = (new DateTimeImmutable())
                    ->modify('+' . $interval . ' days')
                    ->format('Y-m-d H:i:s');
                $update = $pdo->prepare(
                    'UPDATE watering_schedules SET next_watering_at = :next_watering_at
                     WHERE schedule_id = :schedule_id'
                );
                $update->execute([
                    'next_watering_at' => $nextWateringAt,
                    'schedule_id' => $activeSchedule['schedule_id'],
                ]);
                $notification = $pdo->prepare(
                    'INSERT INTO notifications (user_id, schedule_id, message, notification_date)
                     VALUES (:user_id, :schedule_id, :message, NOW())'
                );
                $notification->execute([
                    'user_id' => $userId,
                    'schedule_id' => $activeSchedule['schedule_id'],
                    'message' => $plant['common_name'] . ' was watered. Next reminder in ' . $interval . ' days.',
                ]);
            }
            $pdo->commit();
            setFlash('Watering recorded in your history.');
            redirect('?page=dashboard');
        }

        if ($action === 'save_profile') {
            $firstName = trim((string) ($_POST['first_name'] ?? ''));
            $lastName = trim((string) ($_POST['last_name'] ?? ''));
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $phone = trim((string) ($_POST['phone_number'] ?? ''));
            $newPassword = (string) ($_POST['new_password'] ?? '');
            $confirmPassword = (string) ($_POST['confirm_new_password'] ?? '');
            if ($firstName === '' || $lastName === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Enter your name and a valid email address.');
            }
            if ($newPassword !== '' && strlen($newPassword) < 8) {
                throw new InvalidArgumentException('New password must be at least 8 characters.');
            }
            if ($newPassword !== $confirmPassword) {
                throw new InvalidArgumentException('The new passwords do not match.');
            }
            $profileDirectory = __DIR__ . '/uploads/profile';
            $profileExtensions = ['jpg', 'png', 'webp'];
            $removePicture = isset($_POST['remove_profile_picture']);
            $pictureUpload = $_FILES['profile_picture'] ?? null;
            $pictureExtension = null;
            if (!$removePicture && is_array($pictureUpload) && $pictureUpload['error'] !== UPLOAD_ERR_NO_FILE) {
                if ($pictureUpload['error'] !== UPLOAD_ERR_OK || $pictureUpload['size'] > 2 * 1024 * 1024) {
                    throw new InvalidArgumentException('Choose a profile picture smaller than 2 MB.');
                }
                $imageInfo = getimagesize($pictureUpload['tmp_name']);
                $mimeType = (new finfo(FILEINFO_MIME_TYPE))->file($pictureUpload['tmp_name']);
                $pictureExtension = [
                    'image/jpeg' => 'jpg',
                    'image/png' => 'png',
                    'image/webp' => 'webp',
                ][$mimeType] ?? null;
                if (!$pictureExtension || !$imageInfo || ($imageInfo['mime'] ?? '') !== $mimeType) {
                    throw new InvalidArgumentException('Profile pictures must be JPG, PNG, or WebP images.');
                }
            }
            if ($newPassword === '') {
                $statement = $pdo->prepare(
                    'UPDATE users SET first_name = :first_name, last_name = :last_name,
                     email = :email, phone_number = :phone WHERE user_id = :user_id'
                );
                $parameters = [
                    'first_name' => $firstName, 'last_name' => $lastName, 'email' => $email,
                    'phone' => $phone ?: null, 'user_id' => $userId,
                ];
            } else {
                $statement = $pdo->prepare(
                    'UPDATE users SET first_name = :first_name, last_name = :last_name,
                     email = :email, phone_number = :phone, password_hash = :password_hash
                     WHERE user_id = :user_id'
                );
                $parameters = [
                    'first_name' => $firstName, 'last_name' => $lastName, 'email' => $email,
                    'phone' => $phone ?: null, 'password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
                    'user_id' => $userId,
                ];
            }
            $statement->execute($parameters);

            if ($removePicture) {
                foreach ($profileExtensions as $extension) {
                    $oldPicture = $profileDirectory . '/' . $userId . '.' . $extension;
                    if (is_file($oldPicture) && !unlink($oldPicture)) {
                        throw new RuntimeException('The profile picture could not be removed.');
                    }
                }
            } elseif ($pictureExtension !== null && is_array($pictureUpload)) {
                if (!is_dir($profileDirectory) && !mkdir($profileDirectory, 0755, true) && !is_dir($profileDirectory)) {
                    throw new RuntimeException('The profile picture directory could not be created.');
                }
                $destination = $profileDirectory . '/' . $userId . '.' . $pictureExtension;
                if (!move_uploaded_file($pictureUpload['tmp_name'], $destination)) {
                    throw new RuntimeException('The profile picture could not be saved.');
                }
                foreach ($profileExtensions as $oldExtension) {
                    $oldPicture = $profileDirectory . '/' . $userId . '.' . $oldExtension;
                    if ($oldExtension !== $pictureExtension && is_file($oldPicture) && !unlink($oldPicture)) {
                        throw new RuntimeException('The previous profile picture could not be replaced.');
                    }
                }
            }

            $_SESSION['user_name'] = $firstName;
            setFlash($removePicture ? 'Profile updated and picture removed.' : 'Profile updated.');
            redirect('?page=profile');
        }

        throw new InvalidArgumentException('The requested action is not available.');
    } catch (InvalidArgumentException $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        setFlash($exception->getMessage(), 'error');
        redirect('?page=' . rawurlencode($isAdmin && $page !== 'profile' ? 'admin' : $page));
    } catch (PDOException $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        if (str_contains($exception->getMessage(), 'uq_users_single_admin')) {
            $message = 'Only one administrator account is allowed.';
        } elseif ($exception->getCode() === '23000'
            && in_array($action, ['register', 'register_admin', 'save_profile'], true)) {
            $message = 'That email address is already in use.';
        } else {
            $message = 'The request could not be saved. Please check your details and try again.';
        }
        error_log('Plant Watering Reminder database error: ' . $exception->getMessage());
        setFlash($message, 'error');
        redirect('?page=' . rawurlencode($page));
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $exception;
    }
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$userId = (int) ($_SESSION['user_id'] ?? 0);
$categories = [];
$plants = [];
$schedules = [];
$history = [];
$profile = null;
$users = [];
$dashboardStats = ['plants' => 0, 'due' => 0, 'watered' => 0];
$ownerDueSchedules = [];
$ownerCategoryCounts = [];
$averageWateringInterval = 0;

if ($userId > 0) {
    $categoryStatement = $pdo->query('SELECT category_id, category_name FROM plant_categories ORDER BY category_name');
    $categories = $categoryStatement->fetchAll();

    if ($isAdmin) {
        $users = $pdo->query(
            'SELECT user_id, first_name, last_name, email, role, created_at FROM users ORDER BY created_at DESC'
        )->fetchAll();
        $plants = $pdo->query(
            'SELECT p.plant_id, p.user_id, p.common_name, p.scientific_name, p.category_id,
                    p.watering_frequency_days, p.date_added, p.notes, c.category_name,
                    ws.schedule_id, ws.next_watering_at, ws.repeat_interval_days,
                    CONCAT(u.first_name, " ", u.last_name) AS owner_name, u.email AS owner_email
             FROM plants p
             JOIN users u ON u.user_id = p.user_id
             LEFT JOIN plant_categories c ON c.category_id = p.category_id
             LEFT JOIN watering_schedules ws ON ws.schedule_id = (
                 SELECT MAX(ws2.schedule_id) FROM watering_schedules ws2
                 WHERE ws2.plant_id = p.plant_id AND ws2.active = 1
             )
             ORDER BY p.common_name'
        )->fetchAll();
        $schedules = $pdo->query(
            'SELECT ws.schedule_id, ws.plant_id, ws.next_watering_at, ws.repeat_interval_days, ws.active,
                    p.common_name, p.user_id, CONCAT(u.first_name, " ", u.last_name) AS owner_name
             FROM watering_schedules ws
             JOIN plants p ON p.plant_id = ws.plant_id
             JOIN users u ON u.user_id = p.user_id
             ORDER BY ws.next_watering_at'
        )->fetchAll();
        $dashboardStats['plants'] = count($plants);
        $dashboardStats['due'] = count(array_filter($schedules, static function (array $schedule): bool {
            return (int) $schedule['active'] === 1 && strtotime($schedule['next_watering_at']) <= strtotime('+1 day');
        }));
    } else {
        $plantStatement = $pdo->prepare(
            'SELECT p.plant_id, p.common_name, p.scientific_name, p.category_id, p.watering_frequency_days,
                    p.date_added, p.notes, c.category_name, ws.schedule_id,
                    ws.next_watering_at, ws.repeat_interval_days
             FROM plants p
             LEFT JOIN plant_categories c ON c.category_id = p.category_id
             LEFT JOIN watering_schedules ws ON ws.schedule_id = (
                 SELECT MAX(ws2.schedule_id) FROM watering_schedules ws2
                 WHERE ws2.plant_id = p.plant_id AND ws2.active = 1
             )
             WHERE p.user_id = :user_id
             ORDER BY p.common_name'
        );
        $plantStatement->execute(['user_id' => $userId]);
        $plants = $plantStatement->fetchAll();

        $scheduleStatement = $pdo->prepare(
            'SELECT ws.schedule_id, ws.plant_id, ws.next_watering_at, ws.repeat_interval_days,
                    p.common_name
             FROM watering_schedules ws JOIN plants p ON p.plant_id = ws.plant_id
             WHERE p.user_id = :user_id AND ws.active = 1
             ORDER BY ws.next_watering_at'
        );
        $scheduleStatement->execute(['user_id' => $userId]);
        $schedules = $scheduleStatement->fetchAll();

        $historyStatement = $pdo->prepare(
            'SELECT wh.history_id, wh.watered_at, wh.notes, p.common_name
             FROM watering_history wh JOIN plants p ON p.plant_id = wh.plant_id
             WHERE p.user_id = :user_id ORDER BY wh.watered_at DESC LIMIT 100'
        );
        $historyStatement->execute(['user_id' => $userId]);
        $history = $historyStatement->fetchAll();

        $dashboardStats['plants'] = count($plants);
        $dashboardStats['due'] = count(array_filter($schedules, static function (array $schedule): bool {
            return strtotime($schedule['next_watering_at']) <= strtotime('+1 day');
        }));
        $dashboardStats['watered'] = count(array_filter($history, static function (array $entry): bool {
            return substr($entry['watered_at'], 0, 10) === date('Y-m-d');
        }));
        $ownerDueSchedules = array_values(array_filter($schedules, static function (array $schedule): bool {
            return strtotime($schedule['next_watering_at']) <= strtotime('+1 day');
        }));
        $averageWateringInterval = $plants
            ? (int) round(array_sum(array_column($plants, 'watering_frequency_days')) / count($plants))
            : 0;
        foreach ($categories as $category) {
            $ownerCategoryCounts[$category['category_name']] = 0;
        }
        foreach ($plants as $plant) {
            $categoryName = $plant['category_name'] ?? 'Uncategorized';
            $ownerCategoryCounts[$categoryName] = ($ownerCategoryCounts[$categoryName] ?? 0) + 1;
        }
    }
    $profileStatement = $pdo->prepare(
        'SELECT first_name, last_name, email, phone_number FROM users WHERE user_id = :user_id'
    );
    $profileStatement->execute(['user_id' => $userId]);
    $profile = $profileStatement->fetch();
}
$profileImage = null;
if ($profile && $userId > 0) {
    foreach (['jpg', 'png', 'webp'] as $extension) {
        $imagePath = 'uploads/profile/' . $userId . '.' . $extension;
        if (is_file(__DIR__ . '/' . $imagePath)) {
            $profileImage = $imagePath . '?v=' . filemtime(__DIR__ . '/' . $imagePath);
            break;
        }
    }
    $adminStats = ['admins' => 0, 'overdue' => 0, 'average_interval' => 0];
    $adminCategoryCounts = [];
    $adminDueSchedules = [];
    if ($isAdmin) {
        $adminStats['admins'] = count(array_filter($users, static function (array $user): bool {
            return $user['role'] === 'admin';
        }));
        $adminDueSchedules = array_values(array_filter($schedules, static function (array $schedule): bool {
            return (int) $schedule['active'] === 1 && strtotime($schedule['next_watering_at']) <= strtotime('+1 day');
        }));
        $adminStats['overdue'] = count(array_filter($adminDueSchedules, static function (array $schedule): bool {
            return strtotime($schedule['next_watering_at']) <= time();
        }));
        $adminStats['average_interval'] = $plants
            ? (int) round(array_sum(array_column($plants, 'watering_frequency_days')) / count($plants))
            : 0;
        foreach ($categories as $category) {
            $adminCategoryCounts[$category['category_name']] = 0;
        }
        foreach ($plants as $plant) {
            $categoryName = $plant['category_name'] ?? 'Uncategorized';
            $adminCategoryCounts[$categoryName] = ($adminCategoryCounts[$categoryName] ?? 0) + 1;
        }
    }
}

$search = trim((string) ($_GET['q'] ?? ''));
if (in_array($page, ['plants', 'dashboard'], true) && $search !== '') {
    $plants = array_values(array_filter($plants, static function (array $plant) use ($search): bool {
        return stripos($plant['common_name'], $search) !== false
            || stripos((string) $plant['scientific_name'], $search) !== false
            || stripos((string) ($plant['category_name'] ?? ''), $search) !== false
            || stripos((string) ($plant['notes'] ?? ''), $search) !== false;
    }));
}

$titleMap = [
    'admin' => 'Admin dashboard',
    'statistics' => 'Statistics', 'notifications' => 'Notifications',
    'settings' => 'Settings', 'help' => 'Help & support',
    'dashboard' => 'My Plants', 'plants' => 'My plants', 'plant-form' => 'Plant details',
    'schedules' => 'Watering schedules', 'schedule-form' => 'Schedule details',
    'history' => 'Watering history', 'profile' => 'My profile',
];
$title = $titleMap[$page] ?? ($page === 'role' ? 'Choose your role' : ($page === 'login' ? 'Welcome back' : ($page === 'register' ? 'Create account' : 'Not found')));
$adminSubtitleMap = [
    'admin' => 'Welcome, ' . trim(($profile['first_name'] ?? '') . ' ' . ($profile['last_name'] ?? '')) . '. Manage the whole plant watering system from here.',
    'statistics' => 'System-wide analytics.',
    'notifications' => 'Watering reminders and sensor alerts.',
    'profile' => 'Update your account information and profile picture.',
    'settings' => 'Choose how HappyDrop looks and how your data is used.',
    'help' => 'Getting the most out of HappyDrop.',
];
$adminSubtitle = $adminSubtitleMap[$page] ?? '';
$ownerSubtitleMap = [
    'dashboard' => 'Welcome, ' . trim(($profile['first_name'] ?? '') . ' ' . ($profile['last_name'] ?? '')) . '. Track your plants and watering schedule in one place.',
    'statistics' => 'Insights about your plants.',
    'notifications' => 'Watering reminders and plant care alerts.',
    'profile' => 'Update your account information and profile picture.',
    'settings' => 'Choose how HappyDrop looks and how your data is used.',
    'help' => 'Getting the most out of HappyDrop.',
];
$ownerSubtitle = $ownerSubtitleMap[$page] ?? '';
$isAdminRegistration = $page === 'register' && ($_SESSION['selected_role'] ?? '') === 'admin';
$editingPlant = null;
$editingSchedule = null;
if ($page === 'plant-form' && isset($_GET['id'])) {
    foreach ($plants as $plant) {
        if ((int) $plant['plant_id'] === (int) $_GET['id']) {
            $editingPlant = $plant;
            break;
        }
    }
}
if ($page === 'schedule-form' && isset($_GET['id'])) {
    foreach ($schedules as $schedule) {
        if ((int) $schedule['schedule_id'] === (int) $_GET['id']) {
            $editingSchedule = $schedule;
            break;
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="theme-color" content="<?= $userId ? '#820020' : '#800020' ?>">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="HappyDrop">
    <link rel="manifest" href="manifest.json">
    <link rel="icon" type="image/png" href="assets/HappyDropLogo.png">
    <link rel="apple-touch-icon" href="assets/HappyDropLogo.png">
    <title><?= e($title) ?> | HappyDrop</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/style.css?v=<?= (int) filemtime(__DIR__ . '/assets/style.css') ?>">
    <script>
        try {
            if (!sessionStorage.getItem('happydrop-splash-seen')) {
                document.documentElement.classList.add('show-splash');
            }
        } catch (error) {}
    </script>
</head>
<body class="<?= $userId ? 'app-body admin-theme' . (!$isAdmin ? ' owner-theme' : '') . ($page === 'profile' ? ' profile-page' : '') : 'auth-body' . (in_array($page, ['login', 'register'], true) ? ' auth-split-page' : '') ?>">
<div class="splash-screen" aria-hidden="true">
    <img src="assets/HappyDropLogo.png" alt="">
    <span>Little drops. Happy plants.</span>
</div>
<?php if ($userId): ?>
    <aside class="sidebar<?= $isAdmin ? ' admin-sidebar' : '' ?>">
        <div class="profile-sidebar-user">
            <span class="profile-sidebar-avatar"><?php if ($profileImage): ?><img src="<?= e($profileImage) ?>" alt=""><?php else: ?><span><?= e(strtoupper(substr((string) ($profile['first_name'] ?? ''), 0, 1))) ?></span><?php endif; ?></span>
            <span><strong><?= e(trim(($profile['first_name'] ?? '') . ' ' . ($profile['last_name'] ?? ''))) ?></strong><small><?= $isAdmin ? 'Administrator' : 'Plant Owner' ?></small></span>
        </div>
        <p class="nav-label"><?= $isAdmin ? 'ADMINISTRATION' : 'WORKSPACE' ?></p>
        <nav class="main-nav">
            <?php if ($isAdmin): ?>
                <a class="<?= $page === 'admin' ? 'active' : '' ?>" href="?page=admin" aria-label="Dashboard"><span aria-hidden="true">▦</span><span class="nav-desktop-label">Dashboard</span><span class="nav-mobile-label" aria-hidden="true">Dashboard</span></a>
                <a class="<?= $page === 'statistics' ? 'active' : '' ?>" href="?page=statistics" aria-label="Statistics"><span aria-hidden="true">▥</span><span class="nav-desktop-label">Statistics</span><span class="nav-mobile-label" aria-hidden="true">Statistics</span></a>
                <a class="<?= $page === 'notifications' ? 'active' : '' ?>" href="?page=notifications" aria-label="Notifications"><span aria-hidden="true">♟</span><span class="nav-desktop-label">Notifications</span><span class="nav-mobile-label" aria-hidden="true">Alerts</span><?php if ($adminDueSchedules): ?><span class="admin-notification-count"><?= count($adminDueSchedules) ?></span><?php endif; ?></a>
                <a class="<?= $page === 'profile' ? 'active' : '' ?>" href="?page=profile" aria-label="Profile"><span aria-hidden="true">●</span><span class="nav-desktop-label">Profile</span><span class="nav-mobile-label" aria-hidden="true">Profile</span></a>
                <a class="<?= $page === 'settings' ? 'active' : '' ?>" href="?page=settings" aria-label="Settings"><span aria-hidden="true">⚙</span><span class="nav-desktop-label">Settings</span><span class="nav-mobile-label" aria-hidden="true">Settings</span></a>
                <a class="<?= $page === 'help' ? 'active' : '' ?>" href="?page=help" aria-label="Help and support"><span aria-hidden="true">ⓘ</span><span class="nav-desktop-label">Help &amp; support</span><span class="nav-mobile-label" aria-hidden="true">Help</span></a>
            <?php else: ?>
                <a class="<?= in_array($page, ['dashboard', 'plants', 'plant-form'], true) ? 'active' : '' ?>" href="?page=dashboard" aria-label="Dashboard"><span aria-hidden="true">▦</span><span class="nav-desktop-label">Dashboard</span><span class="nav-mobile-label" aria-hidden="true">Dashboard</span></a>
                <a class="<?= $page === 'statistics' ? 'active' : '' ?>" href="?page=statistics" aria-label="Statistics"><span aria-hidden="true">▥</span><span class="nav-desktop-label">Statistics</span><span class="nav-mobile-label" aria-hidden="true">Statistics</span></a>
                <a class="<?= $page === 'notifications' ? 'active' : '' ?>" href="?page=notifications" aria-label="Notifications"><span aria-hidden="true">♟</span><span class="nav-desktop-label">Notifications</span><span class="nav-mobile-label" aria-hidden="true">Alerts</span><?php if ($ownerDueSchedules): ?><span class="admin-notification-count"><?= count($ownerDueSchedules) ?></span><?php endif; ?></a>
                <a class="<?= $page === 'profile' ? 'active' : '' ?>" href="?page=profile" aria-label="Profile"><span aria-hidden="true">●</span><span class="nav-desktop-label">Profile</span><span class="nav-mobile-label" aria-hidden="true">Profile</span></a>
                <a class="<?= $page === 'settings' ? 'active' : '' ?>" href="?page=settings" aria-label="Settings"><span aria-hidden="true">⚙</span><span class="nav-desktop-label">Settings</span><span class="nav-mobile-label" aria-hidden="true">Settings</span></a>
                <a class="<?= $page === 'help' ? 'active' : '' ?>" href="?page=help" aria-label="Help and support"><span aria-hidden="true">ⓘ</span><span class="nav-desktop-label">Help &amp; support</span><span class="nav-mobile-label" aria-hidden="true">Help</span></a>
            <?php endif; ?>
        </nav>
        <div class="sidebar-bottom">
            <form method="post" class="profile-logout-form"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><button name="action" value="logout"><span aria-hidden="true">⏻</span> Log out</button></form>
        </div>
    </aside>
<?php endif; ?>

<main class="<?= $userId ? 'main-content' : 'auth-main' ?>">
    <?php if ($userId): ?>
        <header class="topbar"><div><h1><?= e($title) ?></h1><p class="admin-page-subtitle"><?= e($isAdmin ? $adminSubtitle : $ownerSubtitle) ?></p></div>
            <div class="topbar-right"><span class="today"><?= e(date('l, F j')) ?></span><button type="button" class="button install-button" id="install-app">Install app</button><a class="notification-badge" href="?page=notifications" title="<?= $dashboardStats['due'] ?> plants due for watering" aria-label="<?= $dashboardStats['due'] ?> plants due for watering">♧<?= $dashboardStats['due'] ? '<b>' . $dashboardStats['due'] . '</b>' : '' ?></a></div>
        </header>
    <?php endif; ?>

    <?php if ($flash): ?><div class="flash <?= e($flash['type']) ?>"><?= e($flash['message']) ?></div><?php endif; ?>

    <?php if ($page === 'role'): ?>
        <section class="auth-card role-card">
            <a class="brand auth-brand" href="?page=role"><img class="brand-logo" src="assets/HappyDropLogo.png" alt=""><span>Happy<span class="brand-light">Drop</span></span></a>
            <div class="auth-illustration"><img src="assets/HappyDropLogo.png" alt=""></div>
            <span class="eyebrow">WELCOME TO HAPPYDROP</span>
            <h1>Choose your role.</h1>
            <p class="muted">Select how you use HappyDrop to continue.</p>
            <div class="role-options">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                    <input type="hidden" name="action" value="select_role">
                    <input type="hidden" name="role" value="plant_owner">
                    <button class="role-option" type="submit"><span class="role-icon">♧</span><span><strong>Plant owner</strong><small>Care for your plants and manage your watering schedule.</small></span><span class="role-arrow">→</span></button>
                </form>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                    <input type="hidden" name="action" value="select_role">
                    <input type="hidden" name="role" value="admin">
                    <button class="role-option" type="submit"><span class="role-icon">⚙</span><span><strong>Administrator</strong>                    <small>Sign in with an existing administrator account to manage HappyDrop.</small></span><span class="role-arrow">→</span></button>
                </form>
            </div>
        </section>
    <?php elseif ($page === 'login' || $page === 'register'): ?>
        <section class="auth-split">
            <header class="auth-hero">
                <a class="auth-hero-logo" href="?page=role" aria-label="HappyDrop home"><img src="assets/HappyDropLogo.png" alt="HappyDrop"></a>
                <h1><?= $page === 'login' ? 'Log In' : 'Sign Up' ?></h1>
            </header>
            <div class="auth-panel">
                <div class="auth-card auth-form-card">
                    <div class="auth-role-tabs" role="group" aria-label="Choose account type">
                        <?php foreach (['plant_owner' => 'Plant Owner', 'admin' => 'Admin'] as $roleValue => $roleLabel): ?>
                            <form method="post">
                                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                                <input type="hidden" name="action" value="select_role">
                                <input type="hidden" name="role" value="<?= e($roleValue) ?>">
                                <input type="hidden" name="next_page" value="<?= e($page) ?>">
                                <button type="submit" class="<?= ($_SESSION['selected_role'] ?? '') === $roleValue ? 'is-active' : '' ?>" aria-pressed="<?= ($_SESSION['selected_role'] ?? '') === $roleValue ? 'true' : 'false' ?>"><?= e($roleLabel) ?></button>
                            </form>
                        <?php endforeach; ?>
                    </div>
                    <?php if ($isAdminRegistration): ?><p class="auth-description">Create the single administrator account using the server secret code.</p><?php endif; ?>
                    <form method="post" class="form-stack">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                        <input type="hidden" name="action" value="<?= $page === 'login' ? 'login' : ($isAdminRegistration ? 'register_admin' : 'register') ?>">
                        <?php if ($page === 'register'): ?>
                            <div class="form-row">
                                <label>First name<input name="first_name" required maxlength="80" autocomplete="given-name" placeholder="Anna"></label>
                                <label>Last name<input name="last_name" required maxlength="80" autocomplete="family-name" placeholder="Reyes"></label>
                            </div>
                        <?php endif; ?>
                        <label>Email address<input type="email" name="email" required maxlength="190" autocomplete="email" placeholder="you@example.com"></label>
                        <?php if ($isAdminRegistration): ?><label>Admin secret code<span class="password-field"><input type="password" name="admin_secret_code" required autocomplete="off" placeholder="Enter the server secret code"><button class="password-toggle" type="button" aria-label="Show admin secret code" aria-pressed="false">Show</button></span></label><?php endif; ?>
                        <label>Password<span class="password-field"><input type="password" name="password" required minlength="<?= $page === 'register' ? '8' : '1' ?>" autocomplete="<?= $page === 'login' ? 'current-password' : 'new-password' ?>" placeholder="<?= $page === 'login' ? 'Enter your password' : 'At least 8 characters' ?>"><button class="password-toggle" type="button" aria-label="Show password" aria-pressed="false">Show</button></span></label>
                        <?php if ($page === 'register'): ?><label>Confirm password<span class="password-field"><input type="password" name="confirm_password" required minlength="8" autocomplete="new-password" placeholder="Re-enter your password"><button class="password-toggle" type="button" aria-label="Show confirm password" aria-pressed="false">Show</button></span></label><?php endif; ?>
                        <button class="button primary full-button"><?= $page === 'login' ? 'Log in' : ($isAdminRegistration ? 'Create Admin account' : 'Create account') ?><span>→</span></button>
                    </form>
                    <p class="auth-switch"><?php if ($page === 'login' && ($_SESSION['selected_role'] ?? '') === 'plant_owner'): ?>Don't have an account? <a href="?page=register">Sign Up</a><?php elseif ($page === 'login' && ($_SESSION['selected_role'] ?? '') === 'admin' && !$adminAccountExists): ?><a href="?page=register">Create the first admin account</a><?php elseif ($page === 'login' && ($_SESSION['selected_role'] ?? '') === 'admin'): ?>An administrator account already exists. Only one admin is allowed.<?php elseif ($page === 'register'): ?>Already have an account? <a href="?page=login">Log In</a><?php endif; ?></p>
                </div>
            </div>
        </section>
    <?php elseif (!$userId): ?>
        <div class="empty-state"><span class="empty-icon">✿</span><h2>Page not found</h2><a href="?page=login">Return to sign in</a></div>
    <?php elseif ($page === 'admin'): ?>
        <section class="admin-stat-grid">
            <article class="admin-stat-card"><strong><?= count($users) ?></strong><span>Registered users</span></article>
            <article class="admin-stat-card"><strong><?= $dashboardStats['plants'] ?></strong><span>Total plants</span></article>
            <article class="admin-stat-card"><strong><?= $adminStats['admins'] ?></strong><span>Administrators</span></article>
            <article class="admin-stat-card"><strong><?= count($adminDueSchedules) ?></strong><span>Due for watering</span></article>
        </section>
        <section class="content-card admin-panel">
            <div class="section-heading"><h2>Registered accounts</h2></div>
            <?php if (!$users): ?><div class="empty-state"><h2>No user accounts found</h2></div>
            <?php else: ?><div class="admin-account-list">
                <?php foreach ($users as $user): ?><article class="admin-account-row">
                    <div class="admin-account-details"><strong><?= e($user['first_name'] . ' ' . $user['last_name']) ?></strong><span><?= e($user['email']) ?></span></div>
                    <span class="admin-role-pill"><?= $user['role'] === 'admin' ? 'Admin' : 'Plant owner' ?></span>
                    <?php if ((int) $user['user_id'] !== $userId): ?>
                        <form method="post" class="admin-user-actions"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="admin_set_user_role"><input type="hidden" name="target_user_id" value="<?= (int) $user['user_id'] ?>"><select name="role" aria-label="Role for <?= e($user['first_name'] . ' ' . $user['last_name']) ?>"><option value="plant_owner" <?= $user['role'] === 'plant_owner' ? 'selected' : '' ?>>Plant owner</option><option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option></select><button class="button outline">Switch role</button></form>
                        <form method="post" onsubmit="return confirm('Delete this user and all related plant records?')"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="admin_delete_user"><input type="hidden" name="target_user_id" value="<?= (int) $user['user_id'] ?>"><button class="button danger-button"><span aria-hidden="true">▤</span> Remove</button></form>
                    <?php else: ?><span class="admin-current-user">Current account</span><?php endif; ?>
                </article><?php endforeach; ?>
            </div><?php endif; ?>
        </section>
        <section class="admin-plants-section">
            <div class="section-heading admin-section-heading"><h2>All plant records</h2><a class="button primary" href="?page=plant-form">＋ Add plant</a></div>
            <?php if (!$plants): ?><div class="content-card empty-state"><h2>No plants have been added</h2><p>Plant records from every account will appear here.</p></div>
            <?php else: ?><div class="admin-plant-grid"><?php foreach ($plants as $plant): $plantIsDue = !empty($plant['next_watering_at']) && strtotime($plant['next_watering_at']) <= time(); ?>
                <article class="admin-plant-card">
                    <span class="admin-category-pill"><?= e($plant['category_name'] ?? 'Uncategorized') ?></span>
                    <h3><?= e($plant['common_name']) ?></h3>
                    <p class="admin-scientific"><?= e($plant['scientific_name'] ?: 'Scientific name not added') ?></p>
                    <p class="admin-plant-owner">Owner: <?= e($plant['owner_name']) ?></p>
                    <span class="admin-due-pill <?= $plantIsDue ? 'is-overdue' : '' ?>"><?= $plantIsDue ? '💧 Overdue for watering' : '💧 ' . (!empty($plant['next_watering_at']) ? 'Watering scheduled' : 'No schedule yet') ?></span>
                    <div class="admin-plant-meta"><span>Every <?= (int) $plant['watering_frequency_days'] ?> days</span><span>Next: <?= !empty($plant['next_watering_at']) ? e(date('M j, Y', strtotime($plant['next_watering_at']))) : 'Not scheduled' ?></span></div>
                    <div class="admin-plant-actions"><a class="button outline" href="?page=plant-form&id=<?= (int) $plant['plant_id'] ?>">Edit</a><form method="post" onsubmit="return confirm('Delete this plant and its watering history?')"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="admin_delete_plant"><input type="hidden" name="plant_id" value="<?= (int) $plant['plant_id'] ?>"><button class="button danger-button">Delete</button></form></div>
                </article>
            <?php endforeach; ?></div><?php endif; ?>
        </section>
        <div class="admin-dashboard-footer"><span>Need to review a watering routine?</span><a class="button outline" href="?page=schedules">Manage all schedules</a></div>
    <?php elseif ($page === 'statistics'): ?>
        <section class="admin-stat-grid">
            <article class="admin-stat-card"><strong><?= $dashboardStats['plants'] ?></strong><span>Plants</span></article>
            <article class="admin-stat-card"><strong><?= $adminStats['overdue'] ?></strong><span>Overdue</span></article>
            <article class="admin-stat-card"><strong><?= $adminStats['average_interval'] ?> days</strong><span>Avg. watering interval</span></article>
            <article class="admin-stat-card"><strong><?= count($users) ?></strong><span>Users</span></article>
        </section>
        <section class="content-card admin-panel">
            <h2>Plants by category</h2>
            <?php $categoryMaximum = max(1, max($adminCategoryCounts ?: [0])); ?>
            <div class="admin-category-list"><?php foreach ($adminCategoryCounts as $categoryName => $categoryCount): ?><div class="admin-category-row"><span><?= e($categoryName) ?></span><span class="admin-bar"><i style="width: <?= (int) round($categoryCount / $categoryMaximum * 100) ?>%"></i></span><span><?= $categoryCount ?></span></div><?php endforeach; ?></div>
        </section>
        <section class="content-card admin-panel">
            <div class="section-heading"><h2>Watering predictions</h2><a class="text-link" href="?page=notifications">View notifications →</a></div>
            <?php if (!$adminDueSchedules): ?><p class="admin-muted">No plants are due for watering in the next 24 hours.</p>
            <?php else: ?><div class="admin-predictions"><?php foreach ($adminDueSchedules as $schedule): ?><div><span aria-hidden="true">♧</span><strong><?= e($schedule['common_name']) ?></strong><small><?= strtotime($schedule['next_watering_at']) <= time() ? 'Overdue' : 'Due soon' ?> · <?= e($schedule['owner_name']) ?></small><span><?= e(date('M j, g:i a', strtotime($schedule['next_watering_at']))) ?></span></div><?php endforeach; ?></div><?php endif; ?>
            <p class="admin-muted">Average interval is calculated from the watering intervals set on plant records.</p>
        </section>
    <?php elseif ($page === 'notifications'): ?>
        <section class="content-card admin-panel admin-notifications">
            <?php $notifications = $isAdmin ? $adminDueSchedules : $ownerDueSchedules; ?>
            <?php if (!$notifications): ?><div class="empty-state"><span class="empty-icon">✓</span><h2>You're all caught up</h2><p>No active watering schedules are due within the next 24 hours.</p></div>
            <?php else: ?><div class="admin-notification-list"><?php foreach ($notifications as $schedule): $isOverdue = strtotime($schedule['next_watering_at']) <= time(); ?>
                <article class="admin-notification-row"><span class="admin-alert-icon">!</span><div><strong><?= e($schedule['common_name']) ?> <?= $isOverdue ? 'is overdue' : 'is due soon' ?></strong><p><?= $isOverdue ? 'Overdue since ' : 'Scheduled for ' ?><?= e(date('M j, Y · g:i a', strtotime($schedule['next_watering_at']))) ?></p><?php if ($isAdmin): ?><small>Owner: <?= e($schedule['owner_name']) ?></small><?php endif; ?></div><?php if (!$isAdmin): ?><form method="post"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="water_plant"><input type="hidden" name="plant_id" value="<?= (int) $schedule['plant_id'] ?>"><button class="button primary">Water now</button></form><?php else: ?><a class="button outline" href="?page=schedules">View schedule</a><?php endif; ?></article>
            <?php endforeach; ?></div><?php endif; ?>
        </section>
    <?php elseif ($page === 'settings'): ?>
        <section class="content-card admin-panel admin-settings-card">
            <h2>Theme</h2>
            <div class="admin-theme-options" role="radiogroup" aria-label="Choose a theme">
                <label class="admin-theme-option" data-theme-option="default"><input type="radio" name="admin-theme" value="default"><span class="theme-swatches"><i></i><i></i><i></i><i></i></span><strong>Default <span class="theme-check" aria-hidden="true"></span></strong></label>
                <label class="admin-theme-option" data-theme-option="light"><input type="radio" name="admin-theme" value="light"><span class="theme-swatches"><i></i><i></i><i></i><i></i></span><strong>Light <span class="theme-check" aria-hidden="true"></span></strong></label>
                <label class="admin-theme-option" data-theme-option="dark"><input type="radio" name="admin-theme" value="dark"><span class="theme-swatches"><i></i><i></i><i></i><i></i></span><strong>Dark <span class="theme-check" aria-hidden="true"></span></strong></label>
            </div>
        </section>
        <section class="content-card admin-panel admin-setting-note"><h2><?= $isAdmin ? 'Account privacy' : 'Your plant data' ?></h2><p><?= $isAdmin ? 'Account details are available to authorized HappyDrop users and administrators. Plant care records are used to manage watering schedules.' : 'Your plant details and watering history help you manage care routines. Your account is protected by your sign-in credentials.' ?></p></section>
        <section class="content-card admin-panel admin-setting-note"><h2>Connection</h2><p>Your account and plant records are saved to the configured HappyDrop database.</p></section>
    <?php elseif ($page === 'help'): ?>
        <?php if ($isAdmin): ?>
            <section class="content-card admin-panel admin-help-card"><h2>Managing HappyDrop</h2><p><strong>Dashboard:</strong> Review registered accounts, plant records, and schedules at a glance.</p><p><strong>Statistics:</strong> See plant totals, watering intervals, overdue schedules, and category counts.</p><p><strong>Notifications:</strong> Check active watering schedules due now or within the next 24 hours.</p></section>
            <section class="content-card admin-panel admin-help-card"><h2>Plant and schedule management</h2><p>Add plant records for an owner, update plant details, or remove records that are no longer needed. Deleting a plant also removes its watering history and schedules.</p><p>Use <a href="?page=schedules">All schedules</a> to review, edit, or remove watering routines.</p></section>
            <section class="content-card admin-panel admin-help-card"><h2>Good to know</h2><p>Watering reminders are based on the dates and intervals saved for each plant.</p><p>Only one administrator account is allowed, and the current admin cannot delete or demote their own account.</p></section>
        <?php else: ?>
            <section class="content-card admin-panel admin-help-card"><h2>Taking care of your plants</h2><p><strong>My Plants:</strong> Add a plant to save its name, category, watering interval, and care notes.</p><p><strong>Watering:</strong> Set a schedule for each plant. When you water it, HappyDrop records the event and moves its next watering date forward.</p><p><strong>Notifications:</strong> Find plants due now or within the next 24 hours.</p></section>
            <section class="content-card admin-panel admin-help-card"><h2>Schedules and history</h2><p>Review or adjust your watering routines and browse your recent watering activity.</p><p><a href="?page=schedules">View watering schedules</a> · <a href="?page=history">View watering history</a></p></section>
            <section class="content-card admin-panel admin-help-card"><h2>Good to know</h2><p>Plant profiles include a suggested watering frequency. Adjust it to suit your plant and growing conditions.</p><p>Your plant records and watering history are linked to your account.</p></section>
        <?php endif; ?>
    <?php elseif ($page === 'statistics' && !$isAdmin): ?>
        <section class="admin-stat-grid owner-stat-grid">
            <article class="admin-stat-card"><strong><?= $dashboardStats['plants'] ?></strong><span>Plants</span></article>
            <article class="admin-stat-card"><strong><?= count(array_filter($ownerDueSchedules, static function (array $schedule): bool { return strtotime($schedule['next_watering_at']) <= time(); })) ?></strong><span>Overdue</span></article>
            <article class="admin-stat-card"><strong><?= $averageWateringInterval ?></strong><span>Avg. watering interval (days)</span></article>
        </section>
        <section class="content-card admin-panel">
            <h2>Plants by category</h2>
            <?php $categoryMaximum = max(1, max($ownerCategoryCounts ?: [0])); ?>
            <?php if (!$ownerCategoryCounts): ?><p class="admin-muted">Add plants to see your collection by category.</p>
            <?php else: ?><div class="admin-category-list"><?php foreach ($ownerCategoryCounts as $categoryName => $categoryCount): ?><div class="admin-category-row"><span><?= e($categoryName) ?></span><span class="admin-bar"><i style="width: <?= (int) round($categoryCount / $categoryMaximum * 100) ?>%"></i></span><span><?= $categoryCount ?></span></div><?php endforeach; ?></div><?php endif; ?>
        </section>
        <section class="content-card admin-panel">
            <div class="section-heading"><h2>Watering predictions</h2><a class="text-link" href="?page=notifications">View notifications →</a></div>
            <?php if (!$ownerDueSchedules): ?><p class="admin-muted">No plants are due for watering in the next 24 hours.</p>
            <?php else: ?><div class="admin-predictions"><?php foreach ($ownerDueSchedules as $schedule): ?><div><span aria-hidden="true">♧</span><strong><?= e($schedule['common_name']) ?></strong><small><?= strtotime($schedule['next_watering_at']) <= time() ? 'Overdue' : 'Due soon' ?></small><span><?= e(date('M j, g:i a', strtotime($schedule['next_watering_at']))) ?></span></div><?php endforeach; ?></div><?php endif; ?>
            <p class="admin-muted">Your average watering interval is calculated from the routines set for your plants.</p>
        </section>
    <?php elseif ($page === 'dashboard'): ?>
        <section class="admin-stat-grid owner-stat-grid">
            <article class="admin-stat-card"><strong><?= $dashboardStats['plants'] ?></strong><span>My plants</span></article>
            <article class="admin-stat-card"><strong><?= $dashboardStats['due'] ?></strong><span>Need water</span></article>
            <article class="admin-stat-card"><strong><?= $dashboardStats['watered'] ?></strong><span>Watered today</span></article>
        </section>
        <div class="page-actions owner-plant-actions"><form class="search-form" method="get"><input type="hidden" name="page" value="dashboard"><span>⌕</span><input type="search" name="q" value="<?= e($search) ?>" placeholder="Search by name, species, category, or notes..."><button>Search</button></form><a class="button primary" href="?page=plant-form">＋ Add plant</a></div>
        <?php if (!$plants): ?><section class="content-card empty-state"><span class="empty-icon">♧</span><h2><?= $search ? 'No plants matched your search' : 'Your garden starts here' ?></h2><p><?= $search ? 'Try another plant name, category, or note.' : 'Add your first plant to start creating a care routine.' ?></p><?php if (!$search): ?><a class="button primary" href="?page=plant-form">Add a plant</a><?php endif; ?></section>
        <?php else: ?><section class="admin-plant-grid owner-plant-grid"><?php foreach ($plants as $plant): $plantIsDue = !empty($plant['next_watering_at']) && strtotime($plant['next_watering_at']) <= strtotime('+1 day'); $plantIsOverdue = !empty($plant['next_watering_at']) && strtotime($plant['next_watering_at']) <= time(); $daysOverdue = $plantIsOverdue ? max(1, (int) floor((time() - strtotime($plant['next_watering_at'])) / 86400)) : 0; ?>
            <article class="admin-plant-card owner-plant-card">
                <span class="admin-category-pill"><?= e($plant['category_name'] ?? 'Uncategorized') ?></span>
                <h3><?= e($plant['common_name']) ?></h3><p class="admin-scientific"><?= e($plant['scientific_name'] ?: 'Add a scientific name') ?></p>
                <?php if ($plantIsDue): ?><span class="admin-due-pill<?= $plantIsOverdue ? ' is-overdue' : '' ?>">💧 <?= $plantIsOverdue ? 'Overdue by ' . $daysOverdue . ' day(s)' : 'Due within 24 hours' ?></span><?php endif; ?>
                <div class="admin-plant-meta"><span>Every <?= (int) $plant['watering_frequency_days'] ?> day(s)</span><span>Next: <?= $plant['next_watering_at'] ? e(date('M j, Y', strtotime($plant['next_watering_at']))) : 'Not scheduled' ?></span></div>
                <?php if ($plant['notes']): ?><p class="admin-muted owner-plant-notes"><?= e($plant['notes']) ?></p><?php endif; ?>
                <div class="admin-plant-actions owner-card-actions"><form method="post"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="water_plant"><input type="hidden" name="plant_id" value="<?= (int) $plant['plant_id'] ?>"><button class="button primary">💧 Water now</button></form><a class="button outline" href="?page=plant-form&amp;id=<?= (int) $plant['plant_id'] ?>">Edit</a><form method="post" onsubmit="return confirm('Delete this plant and its watering history?')"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="delete_plant"><input type="hidden" name="plant_id" value="<?= (int) $plant['plant_id'] ?>"><button class="button danger-button">Delete</button></form></div>
            </article><?php endforeach; ?></section><?php endif; ?>
        <div class="owner-quick-links"><a href="?page=schedules">Manage watering schedules <span>→</span></a><a href="?page=history">View watering history <span>→</span></a></div>
    <?php elseif ($page === 'plants' || $page === 'plant-form'): ?>
        <?php if ($page === 'plant-form'): ?>
        <?php if (isset($_GET['id']) && !$editingPlant): ?><div class="empty-state"><h2>Plant not found</h2><a href="<?= $isAdmin ? '?page=admin' : '?page=dashboard' ?>">Back to <?= $isAdmin ? 'admin dashboard' : 'my plants' ?></a></div>
        <?php else: ?><section class="content-card form-card"><div class="section-heading"><div><span class="eyebrow">PLANT DETAILS</span><h2><?= $editingPlant ? 'Edit plant' : 'Add a new plant' ?></h2></div><a class="text-link" href="<?= $isAdmin ? '?page=admin' : '?page=dashboard' ?>">Cancel</a></div>
                <form method="post" class="form-grid"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="save_plant"><input type="hidden" name="plant_id" value="<?= (int) ($editingPlant['plant_id'] ?? 0) ?>">
                <?php if ($isAdmin): ?><label class="full-span">Plant owner<select name="owner_id" required><option value="">Choose a plant owner</option><?php foreach ($users as $owner): if ($owner['role'] !== 'plant_owner') { continue; } ?><option value="<?= (int) $owner['user_id'] ?>" <?= (int) ($editingPlant['user_id'] ?? 0) === (int) $owner['user_id'] ? 'selected' : '' ?>><?= e($owner['first_name'] . ' ' . $owner['last_name'] . ' · ' . $owner['email']) ?></option><?php endforeach; ?></select></label><?php endif; ?>
                    <label>Plant name *<input name="common_name" required maxlength="120" value="<?= e($editingPlant['common_name'] ?? '') ?>" placeholder="e.g. Monstera"></label>
                    <label>Scientific name<input name="scientific_name" maxlength="150" value="<?= e($editingPlant['scientific_name'] ?? '') ?>" placeholder="e.g. Monstera deliciosa"></label>
                    <label>Category<select name="category_id"><option value="">Choose a category</option><?php foreach ($categories as $category): ?><option value="<?= (int) $category['category_id'] ?>" <?= (int) ($editingPlant['category_id'] ?? 0) === (int) $category['category_id'] ? 'selected' : '' ?>><?= e($category['category_name']) ?></option><?php endforeach; ?></select></label>
                    <label>Water every (days) *<input type="number" name="watering_frequency_days" min="1" max="365" required value="<?= (int) ($editingPlant['watering_frequency_days'] ?? 7) ?>"></label>
                    <label>Date added<input type="date" name="date_added" required value="<?= e($editingPlant['date_added'] ?? date('Y-m-d')) ?>"></label>
                    <label class="full-span">Care notes<textarea name="notes" rows="4" placeholder="Light, soil, or other care notes..."><?= e($editingPlant['notes'] ?? '') ?></textarea></label>
                    <div class="form-actions full-span"><a class="button outline" href="<?= $isAdmin ? '?page=admin' : '?page=dashboard' ?>">Cancel</a><button class="button primary"><?= $editingPlant ? 'Save changes' : 'Add plant' ?></button></div>
                </form>
            </section><?php endif; ?>
        <?php else: ?>
            <div class="page-actions"><form class="search-form" method="get"><input type="hidden" name="page" value="plants"><span>⌕</span><input type="search" name="q" value="<?= e($search) ?>" placeholder="Search your plants..."><button>Search</button></form><a class="button primary" href="?page=plant-form">＋ Add a plant</a></div>
            <?php if (!$plants): ?><section class="content-card empty-state"><span class="empty-icon">♧</span><h2><?= $search ? 'No plants matched your search' : 'Your garden starts here' ?></h2><p><?= $search ? 'Try another plant name.' : 'Add your first plant to start creating a care routine.' ?></p><?php if (!$search): ?><a class="button primary" href="?page=plant-form">Add a plant</a><?php endif; ?></section>
            <?php else: ?><section class="plant-grid"><?php foreach ($plants as $plant): ?><article class="plant-card"><div class="plant-card-top"><span class="plant-thumb large-thumb">♧</span><span class="category-pill"><?= e($plant['category_name'] ?? 'Uncategorized') ?></span><a class="more-link" href="?page=plant-form&id=<?= (int) $plant['plant_id'] ?>" aria-label="Edit <?= e($plant['common_name']) ?>">•••</a></div><h2><?= e($plant['common_name']) ?></h2><p class="scientific"><?= e($plant['scientific_name'] ?: 'Add a scientific name') ?></p><div class="plant-meta"><span>◷ Every <?= (int) $plant['watering_frequency_days'] ?> days</span><span>Next: <?= $plant['next_watering_at'] ? e(date('M j', strtotime($plant['next_watering_at']))) : 'Not scheduled' ?></span></div><?php if ($plant['notes']): ?><p class="plant-notes"><?= e($plant['notes']) ?></p><?php endif; ?><div class="plant-card-actions"><a class="text-link" href="?page=plant-form&id=<?= (int) $plant['plant_id'] ?>">Edit details</a><form method="post" onsubmit="return confirm('Delete this plant and its watering history?')"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="delete_plant"><input type="hidden" name="plant_id" value="<?= (int) $plant['plant_id'] ?>"><button class="danger-link">Delete</button></form></div></article><?php endforeach; ?></section><?php endif; ?>
        <?php endif; ?>
    <?php elseif ($page === 'schedules' || $page === 'schedule-form'): ?>
        <?php if ($page === 'schedule-form'): ?>
            <?php if (!$plants): ?><section class="content-card empty-state"><h2><?= $isAdmin ? 'No plants available' : 'Add a plant first' ?></h2><p>Watering schedules are connected to a plant in a collection.</p><?php if (!$isAdmin): ?><a class="button primary" href="?page=plant-form">Add a plant</a><?php endif; ?></section>
            <?php elseif (isset($_GET['id']) && !$editingSchedule): ?><div class="empty-state"><h2>Schedule not found</h2><a href="?page=schedules">Back to schedules</a></div>
            <?php else: ?><section class="content-card form-card"><div class="section-heading"><div><span class="eyebrow">KEEP YOUR ROUTINE</span><h2><?= $editingSchedule ? 'Edit watering schedule' : 'Create a schedule' ?></h2></div><a class="text-link" href="?page=schedules">Cancel</a></div>
                <form method="post" class="form-grid"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="save_schedule"><input type="hidden" name="schedule_id" value="<?= (int) ($editingSchedule['schedule_id'] ?? 0) ?>">
                    <label>Plant<select name="plant_id" required><?php foreach ($plants as $plant): ?><option value="<?= (int) $plant['plant_id'] ?>" <?= (int) ($editingSchedule['plant_id'] ?? 0) === (int) $plant['plant_id'] ? 'selected' : '' ?>><?= e($plant['common_name']) ?></option><?php endforeach; ?></select></label>
                    <label>Repeat every (days)<input type="number" name="repeat_interval_days" min="1" max="365" required value="<?= (int) ($editingSchedule['repeat_interval_days'] ?? 7) ?>"></label>
                    <label class="full-span">Next watering date and time<input type="datetime-local" name="next_watering_at" required value="<?= e(isset($editingSchedule['next_watering_at']) ? date('Y-m-d\TH:i', strtotime($editingSchedule['next_watering_at'])) : date('Y-m-d\TH:i', strtotime('+1 day 09:00'))) ?>"></label>
                    <div class="form-actions full-span"><a class="button outline" href="?page=schedules">Cancel</a><button class="button primary">Save schedule</button></div>
                </form>
            </section><?php endif; ?>
        <?php else: ?>
            <div class="page-actions"><p class="muted"><?= $isAdmin ? 'Review and manage watering schedules across all plant owners.' : 'Plan a gentle routine for each of your plants.' ?></p><a class="button primary" href="?page=schedule-form">＋ New schedule</a></div>
            <section class="content-card"><?php if (!$schedules): ?><div class="empty-state"><span class="empty-icon">◷</span><h2>No schedules yet</h2><p>Create a schedule so you know when each plant needs a drink.</p><?php if ($plants): ?><a class="button primary" href="?page=schedule-form">Create schedule</a><?php elseif (!$isAdmin): ?><a class="button primary" href="?page=plant-form">Add a plant</a><?php endif; ?></div>
            <?php else: ?><div class="table-wrap"><table><thead><tr><th>PLANT</th><?php if ($isAdmin): ?><th>OWNER</th><?php endif; ?><th>NEXT WATERING</th><th>REPEATS</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody><?php foreach ($schedules as $schedule): $isDue = strtotime($schedule['next_watering_at']) <= time(); ?><tr><td data-label="Plant"><strong><?= e($schedule['common_name']) ?></strong></td><?php if ($isAdmin): ?><td data-label="Owner"><?= e($schedule['owner_name']) ?></td><?php endif; ?><td data-label="Next watering"><?= e(date('M j, Y · g:i a', strtotime($schedule['next_watering_at']))) ?></td><td data-label="Repeats">Every <?= (int) $schedule['repeat_interval_days'] ?> days</td><td data-label="Status"><span class="due-tag <?= $isDue ? 'due-now' : '' ?>"><?= $isDue ? 'Due now' : 'Upcoming' ?></span></td><td class="table-actions" data-label="Actions"><a class="text-link" href="?page=schedule-form&id=<?= (int) $schedule['schedule_id'] ?>">Edit</a><form method="post" onsubmit="return confirm('Delete this watering schedule?')"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="<?= $isAdmin ? 'admin_delete_schedule' : 'delete_schedule' ?>"><input type="hidden" name="schedule_id" value="<?= (int) $schedule['schedule_id'] ?>"><button class="danger-link">Delete</button></form></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?></section>
        <?php endif; ?>
    <?php elseif ($page === 'history'): ?>
        <section class="content-card"><div class="section-heading"><div><span class="eyebrow">YOUR PLANTS, OVER TIME</span><h2>Watering history</h2><p class="muted">A record of your recent plant care.</p></div></div>
            <?php if (!$history): ?><div class="empty-state"><span class="empty-icon">↺</span><h2>No watering history yet</h2><p>Use “Watered” on your dashboard to record plant care.</p></div>
            <?php else: ?><div class="table-wrap"><table><thead><tr><th>PLANT</th><th>WATERED AT</th><th>NOTES</th></tr></thead><tbody><?php foreach ($history as $entry): ?><tr><td data-label="Plant"><strong><?= e($entry['common_name']) ?></strong></td><td data-label="Watered at"><?= e(date('M j, Y · g:i a', strtotime($entry['watered_at']))) ?></td><td data-label="Notes"><?= e($entry['notes'] ?: '—') ?></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
        </section>
    <?php elseif ($page === 'profile'): ?>
        <?php if ($isAdmin): ?>
        <section class="content-card profile-card">
            <form method="post" enctype="multipart/form-data" id="profile-form"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="save_profile">
                <div class="profile-picture">
                    <div class="profile-avatar" id="profile-avatar"><?php if ($profileImage): ?><img src="<?= e($profileImage) ?>" alt="Profile picture"><?php else: ?><span aria-hidden="true"></span><?php endif; ?></div>
                    <h2><?= e(trim(($profile['first_name'] ?? '') . ' ' . ($profile['last_name'] ?? ''))) ?></h2>
                    <p><?= e($profile['email'] ?? '') ?></p>
                    <div class="profile-picture-actions">
                        <input class="profile-picture-input" id="profile-picture-input" type="file" name="profile_picture" accept="image/jpeg,image/png,image/webp">
                        <label class="button primary" for="profile-picture-input"><span aria-hidden="true">▧</span> Upload picture</label>
                        <button class="button outline" type="submit" name="remove_profile_picture" value="1">Remove</button>
                    </div>
                </div>
                <div class="profile-fields">
                    <label>First name<input name="first_name" required maxlength="80" value="<?= e($profile['first_name'] ?? '') ?>"></label>
                    <label>Last name<input name="last_name" required maxlength="80" value="<?= e($profile['last_name'] ?? '') ?>"></label>
                    <label>Email address<input type="email" name="email" required maxlength="190" value="<?= e($profile['email'] ?? '') ?>"></label>
                    <label>Phone number<input type="tel" name="phone_number" maxlength="30" value="<?= e($profile['phone_number'] ?? '') ?>"></label>
                    <label>New password (optional)<span class="password-field"><input type="password" name="new_password" minlength="8" autocomplete="new-password" placeholder="Leave blank to keep your current password"><button class="password-toggle" type="button" aria-label="Show new password" aria-pressed="false">Show</button></span></label>
                    <label>Confirm new password<input type="password" name="confirm_new_password" minlength="8" autocomplete="new-password"></label>
                    <button class="button primary profile-save" type="submit">Save information</button>
                </div>
            </form>
        </section>
        <?php else: ?>
        <section class="content-card form-card profile-card"><div class="section-heading"><div><span class="eyebrow">ACCOUNT SETTINGS</span><h2>Your profile</h2><p class="muted">Keep your contact details up to date.</p></div></div>
            <form method="post" class="form-grid"><input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>"><input type="hidden" name="action" value="save_profile">
                <label>First name<input name="first_name" required maxlength="80" value="<?= e($profile['first_name'] ?? '') ?>"></label>
                <label>Last name<input name="last_name" required maxlength="80" value="<?= e($profile['last_name'] ?? '') ?>"></label>
                <label>Email address<input type="email" name="email" required maxlength="190" value="<?= e($profile['email'] ?? '') ?>"></label>
                <label>Phone number<input type="tel" name="phone_number" maxlength="30" value="<?= e($profile['phone_number'] ?? '') ?>"></label>
                <label class="full-span">New password <span class="muted">(leave blank to keep your current password)</span><span class="password-field"><input type="password" name="new_password" minlength="8" autocomplete="new-password" placeholder="At least 8 characters"><button class="password-toggle" type="button" aria-label="Show new password" aria-pressed="false">Show</button></span></label>
                <div class="form-actions full-span"><button class="button primary">Save profile</button></div>
            </form>
        </section>
        <?php endif; ?>
    <?php else: ?>
        <div class="empty-state"><span class="empty-icon">✿</span><h2>Page not found</h2><a href="?page=dashboard">Return to dashboard</a></div>
    <?php endif; ?>
</main>
<script>
(function () {
    var adminThemeInputs = document.querySelectorAll('input[name="admin-theme"]');
    function setAdminTheme(theme) {
        var activeTheme = ['default', 'light', 'dark'].indexOf(theme) >= 0 ? theme : 'default';
        document.body.setAttribute('data-admin-theme', activeTheme);
        adminThemeInputs.forEach(function (input) {
            var selected = input.value === activeTheme;
            input.checked = selected;
            input.closest('.admin-theme-option').classList.toggle('is-selected', selected);
        });
    }
    if (document.body.classList.contains('admin-theme')) {
        try {
            setAdminTheme(localStorage.getItem('happydrop-admin-theme') || 'default');
        } catch (error) {
            console.error('HappyDrop could not load the saved admin theme:', error);
            setAdminTheme('default');
        }
        adminThemeInputs.forEach(function (input) {
            input.addEventListener('change', function () {
                setAdminTheme(input.value);
                try {
                    localStorage.setItem('happydrop-admin-theme', input.value);
                } catch (error) {
                    console.error('HappyDrop could not save the admin theme:', error);
                }
            });
        });
    }

    var profilePictureInput = document.getElementById('profile-picture-input');
    var profileAvatar = document.getElementById('profile-avatar');
    if (profilePictureInput && profileAvatar) {
        profilePictureInput.addEventListener('change', function () {
            var file = profilePictureInput.files && profilePictureInput.files[0];
            if (!file) return;
            var preview = document.createElement('img');
            preview.alt = 'Selected profile picture preview';
            preview.src = URL.createObjectURL(file);
            profileAvatar.replaceChildren(preview);
        });
    }

    document.querySelectorAll('.password-toggle').forEach(function (toggle) {
        toggle.addEventListener('click', function () {
            var input = toggle.parentElement.querySelector('input');
            var isVisible = input.type === 'text';
            input.type = isVisible ? 'password' : 'text';
            toggle.textContent = isVisible ? 'Show' : 'Hide';
            toggle.setAttribute('aria-label', (isVisible ? 'Show ' : 'Hide ') + (input.name === 'new_password' ? 'new password' : input.name === 'confirm_password' ? 'confirm password' : input.name === 'admin_secret_code' ? 'admin secret code' : 'password'));
            toggle.setAttribute('aria-pressed', String(!isVisible));
        });
    });

    var splash = document.querySelector('.splash-screen');
    if (document.documentElement.classList.contains('show-splash')) {
        try { sessionStorage.setItem('happydrop-splash-seen', '1'); } catch (error) {}
        window.setTimeout(function () {
            document.documentElement.classList.remove('show-splash');
            if (splash) splash.remove();
        }, 1500);
    } else if (splash) {
        splash.remove();
    }

    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function () {
            navigator.serviceWorker.register('service-worker.js').catch(function (error) {
                console.error('HappyDrop service worker registration failed:', error);
            });
        });
    }

    var installButton = document.getElementById('install-app');
    var installPrompt = null;
    if (installButton) {
        window.addEventListener('beforeinstallprompt', function (event) {
            event.preventDefault();
            installPrompt = event;
            installButton.classList.add('is-available');
        });
        installButton.addEventListener('click', async function () {
            if (!installPrompt) return;
            installPrompt.prompt();
            await installPrompt.userChoice;
            installPrompt = null;
            installButton.classList.remove('is-available');
        });
        window.addEventListener('appinstalled', function () {
            installButton.classList.remove('is-available');
        });
    }
}());
</script>
</body>
</html>
