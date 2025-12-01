package security.demo_jwt.domain.model;

public enum AuditAction {
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    REGISTER_SUCCESS,
    LOGOUT,
    PASSWORD_CHANGE,
    ROLE_MANAGEMENT,
    EXCEPTION
}
