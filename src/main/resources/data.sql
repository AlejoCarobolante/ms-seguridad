-- 1. Insertar Permisos
-- (IDs explícitos para no errarle en la relación)
INSERT INTO permissions (id, name) VALUES (1, 'READ_ALL_USERS');
INSERT INTO permissions (id, name) VALUES (2, 'DELETE_USER');
INSERT INTO permissions (id, name) VALUES (3, 'CREATE_ENTITY');
INSERT INTO permissions (id, name) VALUES (4, 'READ_LANDING');

-- 2. Insertar Roles
INSERT INTO roles (id, name) VALUES (1, 'USER');
INSERT INTO roles (id, name) VALUES (2, 'ADMIN');
INSERT INTO roles (id, name) VALUES (3, 'PENDING_VALIDATION');

-- 3. Relacionar Roles con Permisos (Tabla intermedia)
-- Al Admin (ID 2) le damos permiso de Borrar (ID 2) y Crear Parking (ID 3)
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 3);

-- Al Pending Validation (ID 3) le damos permiso de observar la landing page (ID 4)
INSERT INTO roles_permissions (role_id, permission_id) VALUES (3, 4);

-- Al User (ID 1) le damos solo permiso de Leer (ID 1)
INSERT INTO roles_permissions (role_id, permission_id) VALUES (1, 1);