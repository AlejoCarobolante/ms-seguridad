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
public class PasswordRecoverEmailService{
    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;

    public void sendResetEmail(String to, String username, String token){
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            Context context = new Context();
            context.setVariable("username", username);

            String link = "http://localhost:8081/auth/recover-password?token=" + token;
            context.setVariable("link", link);

            String htmlContent = templateEngine.process("reset-password", context);

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("Restablecer tu contraseña");
            helper.setFrom("no-reply@system.com");

            javaMailSender.send(mimeMessage);
        } catch (MessagingException e){
            e.printStackTrace();
        }
    }
}