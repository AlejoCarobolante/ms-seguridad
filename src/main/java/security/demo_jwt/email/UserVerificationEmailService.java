package security.demo_jwt.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.validation.constraints.NotBlank;
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
    private final TemplateEngine templateEngine;

    public void sendVerificationEmail(String to, String username, String code, String organizationName) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            Context context = new Context();
            context.setVariable("username", username);

            String link = "http://localhost:8081/auth/verify?code=" + code;
            context.setVariable("link", link);

            context.setVariable("orgName", organizationName);

            String htmlContent = templateEngine.process("mail-template", context);

            helper.setText(htmlContent, true); // true = Es HTML
            helper.setTo(to);
            helper.setSubject("Activa tu cuenta " + organizationName);
            helper.setFrom("no-reply@system.com");

            javaMailSender.send(mimeMessage);
            System.out.println("Email enviado a: " + to);

        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}