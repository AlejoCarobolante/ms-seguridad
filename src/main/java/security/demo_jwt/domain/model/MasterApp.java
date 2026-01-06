package security.demo_jwt.domain.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "master_apps")
public class MasterApp extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column
    private String description;

    @Column(name = "contact_email")
    private String contactEmail;

    @OneToMany(mappedBy = "masterApp", cascade = CascadeType.ALL)
    private List<ClientApp> tenants;
}
