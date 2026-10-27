# HappyDrop Plant Watering Reminder System

A PHP and MySQL application for keeping plant details, watering schedules, and watering history in one place. Plant owners manage their own collections, while administrators can manage user roles and records across all accounts.

The interface adapts to desktop, tablet, and mobile screen sizes. HappyDrop can also be installed as a Progressive Web App (PWA) in supported browsers; the included logo is used for its app icon and launch splash screen.

## Features

- Account registration, login, logout, and profile updates
- Administrator profile picture uploads (JPG, PNG, or WebP up to 2 MB)
- Role selection before authentication for plant owners and administrators
- Admin dashboard for managing users, plants, and watering schedules
- Plant-owner dashboard with a searchable plant collection, care actions, and watering reminders
- Plant-owner statistics, notifications, profile, appearance settings, and help pages
- Administrator dashboard, system-wide statistics, watering notifications, appearance settings, and help pages
- Owner dashboard with plant totals, upcoming watering, and recent history
- Create, view, update, delete, and search plants
- Create, update, and delete watering schedules
- Record a watering event and automatically move that schedule to its next date
- View the latest 100 watering-history entries
- Plant categories and responsive layouts for desktop, tablet, and mobile
- Installable PWA with HappyDrop branding and a mobile-friendly navigation bar

## Requirements

- PHP 8.1 or newer with `pdo_mysql` enabled
- MySQL 8.0+ or MariaDB 10.4+
- A web server, or PHP's built-in development server

## Setup

1. Start MySQL and import `database.sql` using your MySQL client or phpMyAdmin. If you already have a HappyDrop database, apply the role and single-admin migration before using this version. If the `role` column already exists, skip its `ALTER TABLE` statement. First choose which existing administrator to keep; replace `ADMIN_USER_ID_TO_KEEP` with that account's user ID in the cleanup query:

   ```sql
   ALTER TABLE users
     ADD COLUMN role ENUM('admin', 'plant_owner') NOT NULL DEFAULT 'plant_owner';

   UPDATE users
   SET role = 'plant_owner'
   WHERE role = 'admin' AND user_id <> ADMIN_USER_ID_TO_KEEP;

   ALTER TABLE users
     ADD COLUMN admin_guard TINYINT GENERATED ALWAYS AS (
       CASE WHEN role = 'admin' THEN 1 ELSE NULL END
     ) STORED,
     ADD UNIQUE KEY uq_users_single_admin (admin_guard);
   ```

   The unique database index and server-side role checks both prevent a second administrator. To transfer admin access, verify both IDs, then run a transaction that demotes the current admin before promoting the new one:

   ```sql
   START TRANSACTION;
   UPDATE users SET role = 'plant_owner' WHERE user_id = CURRENT_ADMIN_ID AND role = 'admin';
   UPDATE users SET role = 'admin' WHERE user_id = NEW_ADMIN_ID AND role = 'plant_owner';
   COMMIT;
   ```

2. Configure the database connection. Defaults are `127.0.0.1`, database `plant-watering-system`, user `root`, and an empty password. The app uses the database shown in your phpMyAdmin screenshot. To override these, set `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD` in the PHP server environment.
3. The administrator setup code is `HAPPYDROPADMIN`, configured in `config.php`.

   This is a fixed, easy-to-guess code suitable only for local demonstration. Do not use it on a public or production deployment; replace it with a private environment-configured value before deploying.

4. Open `http://localhost:8000` and create a plant-owner account.
5. To create the single administrator, choose **Administrator**, select **Create the first admin account**, and enter `HAPPYDROPADMIN` along with the account details. Admin registration is only available while no administrator exists. Public registration is only available to plant owners.

The app uses PHP sessions and PDO prepared statements. PWA installation and service workers require HTTPS in deployment (or localhost during development). Set a strong database password and use HTTPS when deploying beyond a local development environment.

## Sessions and database transactions

PHP sessions keep the authenticated user ID and role, the selected sign-in role, CSRF token, and one-time status messages. Login regenerates the session ID, and logout clears the session.

Multi-step database changes use PDO transactions on the InnoDB tables in `database.sql`. The app includes these atomic workflows:

1. **Admin account changes:** deleting an account with its cascaded records, or changing a user's role while protecting the last administrator.
2. **Plant creation:** inserting the plant and its initial watering schedule together.
3. **Recording watering:** inserting the history record, advancing the active schedule, and creating its notification together.

Each workflow commits only after all related database operations succeed. Validation and database failures roll back any open transaction; unexpected errors also roll back before being rethrown.

## Data model

`users` own `plants`; plants optionally belong to a `plant_categories` row and can have watering schedules and watering-history entries. Notifications belong to a user and optionally reference a schedule. Foreign keys clean up a plant's related schedules and history when the plant is deleted.
