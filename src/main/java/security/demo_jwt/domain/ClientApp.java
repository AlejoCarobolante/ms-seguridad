package security.demo_jwt.domain;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "client_apps")
public class ClientApp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer id;

    @Column(nullable = false, unique = true)
    @NotBlank(message = "El nombre del sistema es obliigatorio")
    String name;

    @Column(nullable = false, unique = true)
    @NotBlank(message = "La API KEY es obligatoria")
    String apiKey;
}
