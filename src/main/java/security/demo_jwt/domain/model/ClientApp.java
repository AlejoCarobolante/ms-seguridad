package security.demo_jwt.domain.model;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "client_apps")
@SQLDelete(sql= "UPDATE client_apps SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
@SQLRestriction("deleted_at IS NULL")

public class ClientApp extends BaseEntity{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer id;

    @Column(nullable = false, unique = true)
    @NotBlank(message = "El nombre del sistema es obliigatorio")
    String name;

    @Column(nullable = false, unique = true)
    @NotBlank(message = "La API KEY es obligatoria")
    String apiKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "mfa_policy")
    private MfaPolicy mfaPolicy = MfaPolicy.DISABLED;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "master_app_id")
    private MasterApp masterApp;
}
