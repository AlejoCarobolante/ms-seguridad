package security.demo_jwt.core.security.services;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import security.demo_jwt.domain.repository.AuditLogRepository;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class auditCleanupService {

    private final AuditLogRepository auditLogRepository;

    @Scheduled(cron = "0 0 3 * * *")
    public void deleteOldLogs(){
        LocalDateTime cutOffDate = LocalDateTime.now().minusMonths(6);
        System.out.println("Limpieza de logs en proceso");

        auditLogRepository.deleteByTimestampBefore(cutOffDate);
        System.out.println("Limpieza finalizada");
    }
}
