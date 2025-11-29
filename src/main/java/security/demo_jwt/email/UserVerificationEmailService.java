package security.demo_jwt.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
@RequiredArgsConstructor
public class UserVerificationEmailService {

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine; // <--- 1. Inyectamos el motor de plantillas

    public void sendVerificationEmail(String to, String username, String code) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            // 2. Preparamos las variables que van al HTML
            Context context = new Context();
            context.setVariable("username", username);
            // Armamos el link aquí mismo
            String link = "http://localhost:8081/auth/verify?code=" + code;
            context.setVariable("link", link);

            // 3. Procesamos la plantilla "mail-template.html" con las variables
            String htmlContent = templateEngine.process("mail-template", context);

            helper.setText(htmlContent, true); // true = Es HTML
            helper.setTo(to);
            helper.setSubject("🚀 Activa tu cuenta en Parking App");
            helper.setFrom("no-reply@parking.com");

            javaMailSender.send(mimeMessage);
            System.out.println("✅ Email enviado a: " + to);

        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}