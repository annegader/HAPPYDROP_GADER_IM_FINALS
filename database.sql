CREATE DATABASE IF NOT EXISTS `plant-watering-system`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `plant-watering-system`;

CREATE TABLE IF NOT EXISTS users (
  user_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  first_name VARCHAR(80) NOT NULL,
  last_name VARCHAR(80) NOT NULL,
  email VARCHAR(190) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  phone_number VARCHAR(30) DEFAULT NULL,
  role ENUM('admin', 'plant_owner') NOT NULL DEFAULT 'plant_owner',
  admin_guard TINYINT GENERATED ALWAYS AS (
    CASE WHEN role = 'admin' THEN 1 ELSE NULL END
  ) STORED,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  UNIQUE KEY uq_users_email (email),
  UNIQUE KEY uq_users_single_admin (admin_guard)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS plant_categories (
  category_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  category_name VARCHAR(100) NOT NULL,
  description VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (category_id),
  UNIQUE KEY uq_plant_categories_name (category_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS plants (
  plant_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  category_id INT UNSIGNED DEFAULT NULL,
  common_name VARCHAR(120) NOT NULL,
  scientific_name VARCHAR(150) DEFAULT NULL,
  watering_frequency_days SMALLINT UNSIGNED NOT NULL DEFAULT 7,
  date_added DATE NOT NULL,
  notes TEXT DEFAULT NULL,
  PRIMARY KEY (plant_id),
  KEY idx_plants_user (user_id),
  KEY idx_plants_category (category_id),
  CONSTRAINT fk_plants_user FOREIGN KEY (user_id)
    REFERENCES users (user_id) ON DELETE CASCADE,
  CONSTRAINT fk_plants_category FOREIGN KEY (category_id)
    REFERENCES plant_categories (category_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS watering_schedules (
  schedule_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  plant_id INT UNSIGNED NOT NULL,
  next_watering_at DATETIME NOT NULL,
  repeat_interval_days SMALLINT UNSIGNED NOT NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (schedule_id),
  KEY idx_schedules_plant (plant_id),
  KEY idx_schedules_next (next_watering_at, active),
  CONSTRAINT fk_schedules_plant FOREIGN KEY (plant_id)
    REFERENCES plants (plant_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS watering_history (
  history_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  plant_id INT UNSIGNED NOT NULL,
  watered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  notes VARCHAR(500) DEFAULT NULL,
  PRIMARY KEY (history_id),
  KEY idx_history_plant_date (plant_id, watered_at),
  CONSTRAINT fk_history_plant FOREIGN KEY (plant_id)
    REFERENCES plants (plant_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notifications (
  notification_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  schedule_id INT UNSIGNED DEFAULT NULL,
  message VARCHAR(255) NOT NULL,
  notification_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status ENUM('unread', 'read') NOT NULL DEFAULT 'unread',
  PRIMARY KEY (notification_id),
  KEY idx_notifications_user_status (user_id, status, notification_date),
  CONSTRAINT fk_notifications_user FOREIGN KEY (user_id)
    REFERENCES users (user_id) ON DELETE CASCADE,
  CONSTRAINT fk_notifications_schedule FOREIGN KEY (schedule_id)
    REFERENCES watering_schedules (schedule_id) ON DELETE SET NULL
) ENGINE=InnoDB;

INSERT IGNORE INTO plant_categories (category_name, description) VALUES
  ('Indoor', 'Plants usually grown indoors'),
  ('Outdoor', 'Plants usually grown outdoors'),
  ('Succulent', 'Succulents and cacti'),
  ('Herb', 'Culinary and medicinal herbs');
