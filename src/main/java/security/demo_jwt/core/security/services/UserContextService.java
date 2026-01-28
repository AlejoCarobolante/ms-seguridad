package security.demo_jwt.core.security.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.domain.repository.UserRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Service
@RequiredArgsConstructor
public class UserContextService {

    public User getCurrentUser() {
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Usuario no autenticado");
        }

        Object principal = authentication.getPrincipal();

        if (!(principal instanceof User user)) {
            throw new AccessDeniedException("Principal inválido");
        }

        return user;
    }

    public boolean isSuperAdmin() {
        return getCurrentUser().getRoles()
                .stream()
                .anyMatch(r -> r.getName().equals("ROLE_SUPER_ADMIN"));
    }

    public boolean isTenantAdmin() {
        return getCurrentUser().getRoles()
                .stream()
                .anyMatch(r -> r.getName().equals("ROLE_TENANT_ADMIN"));
    }

    public boolean isReadOnly() {
        return getCurrentUser().getRoles()
                .stream()
                .anyMatch(r -> r.getName().equals("ROLE_SUPPORT"));
    }
}

