package security.demo_jwt.core.security.services;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.demo_jwt.domain.model.AuditAction;
import security.demo_jwt.domain.model.AuditLog;
import security.demo_jwt.domain.repository.AuditLogRepository;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public void log(AuditAction action, String email, String detail, String appName, HttpServletRequest request){
        String ip = "Unknown";
        if(request != null){
            ip = request.getHeader("X-Forwarded-For");
            if(ip == null) ip = request.getRemoteAddr();
        }

        AuditLog logEntry = AuditLog.builder()
                .action(action)
                .email(email)
                .description(detail)
                .clientAppName(appName)
                .ipAdress(ip)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(logEntry);
    }
}
