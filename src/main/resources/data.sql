
INSERT INTO permissions (id, name) VALUES (1, 'READ_ALL_USERS');
INSERT INTO permissions (id, name) VALUES (2, 'DELETE_USER');
INSERT INTO permissions (id, name) VALUES (3, 'CREATE_ENTITY');
INSERT INTO permissions (id, name) VALUES (4, 'READ_LANDING');

INSERT INTO roles (id, name) VALUES (1, 'USER');
INSERT INTO roles (id, name) VALUES (2, 'ADMIN');
INSERT INTO roles (id, name) VALUES (3, 'PENDING_VALIDATION');

INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2);
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 3);

INSERT INTO roles_permissions (role_id, permission_id) VALUES (3, 4);

INSERT INTO roles_permissions (role_id, permission_id) VALUES (1, 1);

INSERT INTO client_apps (name, api_key) VALUES ('Parking System Corp.', 'PARKING_KEY_123');