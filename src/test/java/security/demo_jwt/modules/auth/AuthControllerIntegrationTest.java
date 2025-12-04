package security.demo_jwt.modules.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import security.demo_jwt.domain.model.ClientApp;
import security.demo_jwt.domain.model.Role;
import security.demo_jwt.domain.repository.ClientAppRepository;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.modules.auth.dto.RegisterRequest;

import java.util.Date;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest // Levanta todo el contexto de Spring
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ClientAppRepository clientAppRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private ObjectMapper objectMapper; // Para convertir objetos a JSON

    @Test
    void shouldRegisterUserSuccessfully() throws Exception {
        // 1. PREPARAR BASE DE DATOS (Necesitamos datos previos)
        // Como es H2 de test, está vacía. Insertamos lo mínimo.
        if(roleRepository.findByName("PENDING_VALIDATION").isEmpty()){
            roleRepository.save(Role.builder().name("PENDING_VALIDATION").build());
        }

        String apiKey = "INTEGRATION-KEY";
        if(clientAppRepository.findByApiKey(apiKey).isEmpty()){
            clientAppRepository.save(ClientApp.builder().name("Integration App").apiKey(apiKey).build());
        }

        // 2. CREAR REQUEST
        RegisterRequest request = new RegisterRequest();
        request.setUsername("integrationUser");
        request.setPassword("Strong@Pass1");
        request.setFirstName("Int");
        request.setLastName("Test");
        request.setEmail("integration@test.com");
        request.setDateOfBirth(new Date());

        // 3. DISPARAR PETICIÓN Y VERIFICAR
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Client-Id", apiKey) // <--- Importante: Header Multi-Tenant
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk()) // Esperamos 200 OK
                .andExpect(jsonPath("$.access_token").exists()); // Esperamos que devuelva un token
    }
}