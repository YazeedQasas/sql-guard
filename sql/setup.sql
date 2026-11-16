-- sql-guard demo setup.
-- Run once in MySQL Workbench as root (File > Open SQL Script, then the lightning bolt).
-- Re-running is safe: it drops and recreates the demo database and user.
--
-- BEFORE RUNNING: replace  change-me-ro-password  below with a password of your
-- own, and put the same value in .env as SQLGUARD_DB_PASSWORD.

DROP DATABASE IF EXISTS sqlguard_demo;
CREATE DATABASE sqlguard_demo CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE sqlguard_demo;

CREATE TABLE customers (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(100) NOT NULL,
    email       VARCHAR(200) NOT NULL,
    country     VARCHAR(2)   NOT NULL,
    created_at  DATE         NOT NULL
);

CREATE TABLE products (
    id      INT PRIMARY KEY AUTO_INCREMENT,
    name    VARCHAR(100)  NOT NULL,
    price   DECIMAL(10,2) NOT NULL
);

CREATE TABLE orders (
    id           INT PRIMARY KEY AUTO_INCREMENT,
    customer_id  INT NOT NULL,
    product_id   INT NOT NULL,
    quantity     INT NOT NULL,
    total        DECIMAL(10,2) NOT NULL,
    ordered_at   DATE NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(id),
    FOREIGN KEY (product_id)  REFERENCES products(id)
);

-- NOT on the allowlist and NOT granted to the read-only user.
CREATE TABLE secrets (
    id       INT PRIMARY KEY AUTO_INCREMENT,
    api_key  VARCHAR(100) NOT NULL
);

INSERT INTO customers (name, email, country, created_at) VALUES
  ('Lina Haddad',    'lina@example.com',    'JO', '2026-01-04'),
  ('Omar Khalil',    'omar@example.com',    'JO', '2026-01-19'),
  ('Sara Nasser',    'sara@example.com',    'AE', '2026-02-02'),
  ('James Carter',   'james@example.com',   'US', '2026-02-11'),
  ('Mei Tanaka',     'mei@example.com',     'JP', '2026-03-08'),
  ('Yousef Amin',    'yousef@example.com',  'SA', '2026-03-21'),
  ('Elena Rossi',    'elena@example.com',   'IT', '2026-04-15'),
  ('Karim Saleh',    'karim@example.com',   'EG', '2026-05-01');

INSERT INTO products (name, price) VALUES
  ('Notebook', 4.50), ('Pen pack', 2.25), ('Backpack', 39.00),
  ('Desk lamp', 24.99), ('Headphones', 79.00);

-- 300 orders so the row cap has something to cap.
INSERT INTO orders (customer_id, product_id, quantity, total, ordered_at)
WITH RECURSIVE seq (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 300)
SELECT 1 + (n * 7) % 8,
       1 + (n * 3) % 5,
       1 + n % 4,
       (1 + n % 4) * ELT(1 + (n * 3) % 5, 4.50, 2.25, 39.00, 24.99, 79.00),
       DATE_ADD('2026-01-01', INTERVAL n % 300 DAY)
FROM seq;

INSERT INTO secrets (api_key) VALUES ('sk-live-this-must-never-leak');

-- Read-only user: SELECT on the allowlisted tables only. Nothing else.
DROP USER IF EXISTS 'sqlguard_ro'@'localhost';
CREATE USER 'sqlguard_ro'@'localhost' IDENTIFIED BY 'change-me-ro-password';
GRANT SELECT ON sqlguard_demo.customers TO 'sqlguard_ro'@'localhost';
GRANT SELECT ON sqlguard_demo.products  TO 'sqlguard_ro'@'localhost';
GRANT SELECT ON sqlguard_demo.orders    TO 'sqlguard_ro'@'localhost';
FLUSH PRIVILEGES;

-- Sanity check: should show three SELECT grants and nothing else.
SHOW GRANTS FOR 'sqlguard_ro'@'localhost';
