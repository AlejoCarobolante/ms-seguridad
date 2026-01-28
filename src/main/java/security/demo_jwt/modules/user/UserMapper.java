package security.demo_jwt.modules.user;

import security.demo_jwt.domain.model.Role;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.modules.user.dto.UserProfileResponse;

import java.util.stream.Collectors;

public class UserMapper {

    public static UserProfileResponse toUserProfileResponse(User user) {
        return UserProfileResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .build();
    }
}