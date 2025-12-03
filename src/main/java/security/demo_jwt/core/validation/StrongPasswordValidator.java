package security.demo_jwt.core.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        // Expresión Regular para "Password Fuerte" (IA helped here)
        // ^                 : Inicio
        // (?=.*[0-9])       : Al menos un dígito
        // (?=.*[a-z])       : Al menos una minúscula
        // (?=.*[A-Z])       : Al menos una mayúscula
        // (?=.*[@#$%^&+=!]) : Al menos un carácter especial (puedes agregar más)
        // (?=\S+$)          : Sin espacios en blanco
        // .{8,}             : Al menos 8 caracteres
        // $                 : Fin
        return value.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$");
    }
}