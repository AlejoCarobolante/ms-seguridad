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

    public void sendVerificationEmail(String to, String username) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlMsg = String.format(
                    "<div style='font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd;'>" +
                            "  <h2>Hola %s,</h2>" +
                            "  <p>Gracias por registrarte en el sistema de Parking.</p>" +
                            "  <p>Tu cuenta ha sido creada correctamente y está pendiente de validación.</p>" +
                            "  <br>" +
                            "  <p>Te avisaremos cuando esté activa.</p>" +
                            "</div>",
                    username
            );

            helper.setText(htmlMsg, true);
            helper.setTo(to);
            helper.setSubject("Bienvenido - Verificación de Cuenta");
            helper.setFrom("no-reply@parking.com");

            javaMailSender.send(mimeMessage);
            System.out.println("✅ Email enviado a: " + to);

        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
    }