-- 1. CLIENT APPS
INSERT INTO client_apps (id, name, api_key) VALUES (1, 'Parking System Corp.', 'PARKING_KEY_123');

-- 2. PERMISSIONS
INSERT INTO permissions (id, name) VALUES (1, 'READ_ALL_USERS');
INSERT INTO permissions (id, name) VALUES (2, 'DELETE_USER');
INSERT INTO permissions (id, name) VALUES (3, 'CREATE_ENTITY');
INSERT INTO permissions (id, name) VALUES (4, 'READ_LANDING');

-- 3. USERS
-- Corregido: Solo usamos las columnas que tienes en tu entidad User.java actual.
-- Eliminados: failed_login_attempts, mfa_enabled, mfa_secret
INSERT INTO users (
    id,
    username,
    password,
    email,
    date_of_birth,
    first_name,
    last_name,
    verification_code,
    client_app_id,
    account_locked
)
VALUES (
    1,
    'rootadmin',
    '$2a$10$TU_HASH_GENERADO_AQUI',
    'root@admin.com',
    '2000-01-01',
    'System',
    'Admin',
    NULL,
    1,
    false
);

-- 4. ROLES
INSERT INTO roles (id, client_app_id, creator_user_id, name) VALUES (1, 1, 1, 'USER');
INSERT INTO roles (id, client_app_id, creator_user_id, name) VALUES (2, 1, 1, 'ADMIN');
INSERT INTO roles (id, client_app_id, creator_user_id, name) VALUES (3, 1, 1, 'PENDING_VALIDATION');

-- 5. RELACIONES
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 3);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (3, 4);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (1, 1);

-- 6. RESETEAR CONTADORES (Vital para H2)
ALTER TABLE client_apps ALTER COLUMN id RESTART WITH 100;
ALTER TABLE users ALTER COLUMN id RESTART WITH 100;
ALTER TABLE roles ALTER COLUMN id RESTART WITH 100;
ALTER TABLE permissions ALTER COLUMN id RESTART WITH 100;