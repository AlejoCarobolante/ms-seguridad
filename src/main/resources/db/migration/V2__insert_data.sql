
INSERT INTO client_apps (id, name, api_key) VALUES (100, 'Parking System Corp.', 'PARKING_KEY_123');

INSERT INTO permissions (id, name) VALUES (1, 'READ_ALL_USERS');
INSERT INTO permissions (id, name) VALUES (2, 'DELETE_USER');
INSERT INTO permissions (id, name) VALUES (3, 'CREATE_ENTITY');
INSERT INTO permissions (id, name) VALUES (4, 'READ_LANDING');

INSERT INTO users (id, username, password, email, date_of_birth, first_name, last_name, client_app_id, account_locked)
VALUES (100, 'rootadmin', '$2a$10$TU_HASH_AQUI', 'root@admin.com', '2000-01-01', 'System', 'Admin', 100, false);

INSERT INTO roles (id, client_app_id, creator_user_id, name) VALUES (1, 100, 100, 'USER');
INSERT INTO roles (id, client_app_id, creator_user_id, name) VALUES (2, 100, 100, 'ADMIN');

INSERT INTO users_roles (user_id, roles_id) VALUES (100, 2);

INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 1);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2);

ALTER TABLE client_apps ALTER COLUMN id RESTART WITH 200;
ALTER TABLE users ALTER COLUMN id RESTART WITH 200;
ALTER TABLE roles ALTER COLUMN id RESTART WITH 200;