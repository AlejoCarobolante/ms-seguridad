INSERT INTO client_apps (id, name, api_key, created_at, updated_at)
VALUES (100, 'Parking System Corp.', 'PARKING_KEY_123', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO client_apps (name, api_key, created_at, updated_at)
VALUES ('Security Admin Panel', 'SEC_MASTER_KEY_999', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, isSysOnly, created_at, updated_at) VALUES
('READ_ALL_USERS', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('DELETE_USER', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('CREATE_ENTITY', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('READ_LANDING', false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('PERMISSION_CREATE_ROLE', false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('PERMISSION_VIEW_AUDIT', false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO users (id, username, password, email, date_of_birth, first_name, last_name, client_app_id, account_locked, created_at, updated_at)
VALUES (100, 'rootadmin', '$2a$10$TU_HASH_AQUI', 'root@admin.com', '2000-01-01', 'System', 'Admin', 100, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

ALTER TABLE roles ALTER COLUMN id RESTART WITH 200;

INSERT INTO roles (client_app_id, creator_user_id, name, created_at, updated_at)
VALUES (100, 100, 'USER', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO roles (client_app_id, creator_user_id, name, created_at, updated_at)
VALUES (100, 100, 'ADMIN', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO roles (client_app_id, creator_user_id, name, created_at, updated_at)
VALUES (
    (SELECT id FROM client_apps WHERE api_key = 'SEC_MASTER_KEY_999'),
    100,
    'PENDING_VALIDATION',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT INTO roles (name, client_app_id, created_at, updated_at)
VALUES
('ROLE_SUPER_ADMIN', (SELECT id FROM client_apps WHERE api_key = 'SEC_MASTER_KEY_999'), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('ROLE_SUPPORT', (SELECT id FROM client_apps WHERE api_key = 'SEC_MASTER_KEY_999'), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO users_roles (user_id, roles_id)
VALUES (100, (SELECT id FROM roles WHERE name = 'ADMIN' AND client_app_id = 100));

INSERT INTO roles_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE name = 'ADMIN' AND client_app_id = 100), id
FROM permissions WHERE name IN ('READ_ALL_USERS', 'DELETE_USER');

INSERT INTO roles_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'ROLE_SUPER_ADMIN' AND p.name = 'PERMISSION_CREATE_ROLE';

ALTER TABLE client_apps ALTER COLUMN id RESTART WITH 200;
ALTER TABLE users ALTER COLUMN id RESTART WITH 200;
ALTER TABLE roles ALTER COLUMN id RESTART WITH 200;