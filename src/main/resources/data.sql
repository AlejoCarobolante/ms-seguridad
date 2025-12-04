-- 1. CLIENT APPS (Upsert)
MERGE INTO client_apps (id, name, api_key)
KEY(id)
VALUES (1, 'Parking System Corp.', 'PARKING_KEY_123');

-- 2. PERMISSIONS (Upsert)
MERGE INTO permissions (id, name) KEY(id) VALUES (1, 'READ_ALL_USERS');
MERGE INTO permissions (id, name) KEY(id) VALUES (2, 'DELETE_USER');
MERGE INTO permissions (id, name) KEY(id) VALUES (3, 'CREATE_ENTITY');
MERGE INTO permissions (id, name) KEY(id) VALUES (4, 'READ_LANDING');

-- 3. USERS (Upsert)
-- Asegúrate de que el hash de la contraseña sea válido
MERGE INTO users (id, username, password, email, date_of_birth, first_name, last_name, verification_code, client_app_id)
KEY(id)
VALUES (1, 'rootadmin', '$2a$10$TU_HASH_GENERADO_AQUI', 'root@admin.com', '2000-01-01', 'System', 'Admin', NULL, 1);

-- 4. ROLES (Upsert)
MERGE INTO roles (id, client_app_id, creator_user_id, name) KEY(id) VALUES (1, 1, 1, 'USER');
MERGE INTO roles (id, client_app_id, creator_user_id, name) KEY(id) VALUES (2, 1, 1, 'ADMIN');
MERGE INTO roles (id, client_app_id, creator_user_id, name) KEY(id) VALUES (3, 1, 1, 'PENDING_VALIDATION');

-- 5. RELACIONES (Limpiar e insertar de nuevo para evitar duplicados en tablas sin PK simple)
DELETE FROM roles_permissions;

INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 3);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (3, 4);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (1, 1);