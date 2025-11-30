package security.demo_jwt.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Column(nullable = false)
    String email;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    AuditAction action;

    @Column
    String description;

    @Column
    String ipAdress;

    @Column
    String clientAppName;

    @Column(nullable = false)
    LocalDateTime timestamp;
}
