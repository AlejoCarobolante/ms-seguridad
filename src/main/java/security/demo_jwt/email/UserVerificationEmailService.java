package security.demo_jwt.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserVerificationEmailService {

    private final JavaMailSender javaMailSender;

    // 1. AHORA RECIBIMOS EL CÓDIGO TAMBIÉN
    public void sendVerificationEmail(String to, String username, String code) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            // 2. ARMAMOS EL LINK REAL (Apunta a tu propio endpoint)
            String link = "http://localhost:8081/auth/verify?code=" + code;

            // 3. HTML CON EL BOTÓN Y 3 VARIABLES (%s)
            String htmlMsg = String.format(
                    "<div style='font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd;'>" +
                            "  <h2>Hola %s,</h2>" +
                            "  <p>Gracias por registrarte. Para activar tu cuenta, necesitamos verificar tu email.</p>" +
                            "  <br>" +
                            "  <div style='text-align: center; margin: 20px 0;'>" +
                            "    <a href='%s' style='background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;'>VERIFICAR MI CUENTA</a>" +
                            "  </div>" +
                            "  <p>Si el botón no funciona, tu código manual es: <b>%s</b></p>" +
                            "  <br>" +
                            "  <p>Saludos,<br>El equipo de Parking</p>" +
                            "</div>",
                    username, link, code // <--- 3 VARIABLES QUE COINCIDEN CON LOS 3 %s DE ARRIBA
            );

            helper.setText(htmlMsg, true);
            helper.setTo(to);
            helper.setSubject("Acción Requerida: Verifica tu cuenta");
            helper.setFrom("no-reply@parking.com");

            javaMailSender.send(mimeMessage);
            System.out.println("✅ Email de verificación enviado a: " + to);

        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}