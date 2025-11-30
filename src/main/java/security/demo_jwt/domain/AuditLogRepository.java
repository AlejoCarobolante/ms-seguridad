package security.demo_jwt.domain;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;

public interface AuditLogRepository extends JpaRepository<AuditLog, Integer> {

    @Transactional
    void deleteByTimestampBefore(LocalDateTime cutoffDate);
}
