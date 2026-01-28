-- Insertar Master App
INSERT INTO master_apps (name, description, contact_email, created_at)
VALUES ('Parking Soft Inc.', 'Sistema Maestro', 'admin@parkingsoft.com', CURRENT_TIMESTAMP);

-- Insertar Tenant (Client App)
INSERT INTO client_apps (name, api_key, mfa_policy, master_app_id, created_at)
VALUES ('Parking Central', 'PARKING_KEY_123', 'DISABLED', 1, CURRENT_TIMESTAMP);

-- Insertar Usuario Root (Password: Password123!)
-- Ajusta el hash si usas otro encoder, este es BCrypt standard
INSERT INTO users (email, password, first_name, last_name, username, date_of_birth, client_app_id, enabled, created_at)
VALUES ('root@admin.com', '$2a$10$wW.w..p.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.w.', 'Super', 'Admin', 'rootadmin', '1990-01-01 00:00:00', 1, true, CURRENT_TIMESTAMP);

-- Insertar Roles y Permisos
INSERT INTO roles (name, client_app_id, creator_user_id, created_at)
VALUES ('ADMIN', 1, 1, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, is_sys_only, created_at) VALUES ('READ_ALL', true, CURRENT_TIMESTAMP);

-- Asignar Rol a Usuario
INSERT INTO users_roles (user_id, roles_id) VALUES (1, 1);