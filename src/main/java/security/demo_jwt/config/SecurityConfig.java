package security.demo_jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    //private final AuthenticationProvider authenticationProvider;
    @Bean
    public SecurityFilterChain  securityFilterChain(HttpSecurity http) {

        return http
            .csrf(csrf -> csrf.disable()) //No se usan cookies
            .authorizeHttpRequests(authRequest ->
                authRequest
                .requestMatchers("/auth/**").permitAll() //rutas públicas
                .anyRequest().authenticated() //rutas protegidas
            )
            .sessionManagement(sessionManager ->
                sessionManager
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // La sesion es stateless. Si vas a una ruta privada te da error 403 en lugar de redirigirte al login
            )
            //.authenticationProvider(authenticationProvider)
            .build();
    }
}
