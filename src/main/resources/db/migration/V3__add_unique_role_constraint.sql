ALTER TABLE roles
ADD CONSTRAINT uk_role_name_per_tenant
UNIQUE (name, client_app_id);