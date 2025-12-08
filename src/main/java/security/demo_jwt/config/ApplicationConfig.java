package security.demo_jwt.config;

import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import security.demo_jwt.domain.model.ClientApp;
import security.demo_jwt.domain.repository.ClientAppRepository;
import security.demo_jwt.domain.repository.UserRepository;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;
    private final ClientAppRepository clientAppRepository;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
    return authenticationProvider;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return input -> {
            if(input.contains(":")){
                String[] parts = input.split(":");
                String email = parts[0];
                String apiKey = parts[1];

                ClientApp app = clientAppRepository.findByApiKey(apiKey)
                        .orElseThrow(()-> new UsernameNotFoundException("App no valida."));

                return userRepository.findByEmailAndClientApp(email, app)
                        .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
            }

            try {
                Integer userId = Integer.parseInt(input);
                return userRepository.findById(userId)
                        .orElseThrow(()-> new UsernameNotFoundException("Usuario no encontrado"));
            } catch (NumberFormatException e){
                throw new UsernameNotFoundException("Formato de identificador no valido: " + input);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }
}