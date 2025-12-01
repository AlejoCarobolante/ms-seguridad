package security.demo_jwt.domain.repository;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import security.demo_jwt.domain.model.AuditLog;

import java.time.LocalDateTime;

public interface AuditLogRepository extends JpaRepository<AuditLog, Integer> {

    @Transactional
    void deleteByTimestampBefore(LocalDateTime cutoffDate);
}
