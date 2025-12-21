package security.demo_jwt.modules.common.dto;

import java.time.LocalDateTime;
import java.util.List;

public record ErrorResponse(
        int status,
        String message,
        String path,
        LocalDateTime timestamp,
        List<String> errors
) {
    public ErrorResponse(int status, String message, String path) {
        this(status, message, path, LocalDateTime.now(), null);
    }
}