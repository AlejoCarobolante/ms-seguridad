package security.demo_jwt.core.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

    String message() default "La contraseña debe tener al menos 8 caracteres, mayúscula, minúscula, número y carácter especial.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}