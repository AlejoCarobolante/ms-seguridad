-- *** 1. ENTIDADES INDEPENDIENTES (Sin FK hacia otros lugares) ***

-- INSERT CLIENT_APPS (PADRE DE TODOS)
-- Necesita ejecutarse primero para que USERS y ROLES puedan referenciarlo.
INSERT INTO client_apps (id, name, api_key) VALUES (1, 'Parking System Corp.', 'PARKING_KEY_123');

-- INSERT PERMISSIONS (No tiene dependencias)
INSERT INTO permissions (id, name) VALUES (1, 'READ_ALL_USERS');
INSERT INTO permissions (id, name) VALUES (2, 'DELETE_USER');
INSERT INTO permissions (id, name) VALUES (3, 'CREATE_ENTITY');
INSERT INTO permissions (id, name) VALUES (4, 'READ_LANDING');

-- *** 2. ENTIDADES DEPENDIENTES ***

-- INSERT USERS (Requiere CLIENT_APP_ID = 1)
-- El ID del Admin ya es seguro (ID=1)
INSERT INTO users (id, username, password, email, date_of_birth, first_name, last_name, verification_code, client_app_id)
VALUES (1, 'rootadmin', '$2a$10$TU_HASH_GENERADO_AQUI', 'root@admin.com', '2000-01-01', 'System', 'Admin', NULL, 1); -- OK

-- *** 3. ROLES (Requiere USERS y CLIENT_APPS) ***
SET @admin_id = 1;
SET @parking_app_id = 1;

INSERT INTO roles (id, client_app_id, creator_user_id, name)
VALUES (1, @parking_app_id, @admin_id, 'USER');

INSERT INTO roles (id, client_app_id, creator_user_id, name)
VALUES (2, @parking_app_id, @admin_id, 'ADMIN');

INSERT INTO roles (id, client_app_id, creator_user_id, name)
VALUES (3, @parking_app_id, @admin_id, 'PENDING_VALIDATION');

-- *** 4. RELACIONES ***

INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 3);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (3, 4);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (1, 1);