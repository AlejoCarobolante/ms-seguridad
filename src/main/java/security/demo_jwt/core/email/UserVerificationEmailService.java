package security.demo_jwt.core.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.springframework.beans.factory.annotation.Value;
@Service
@RequiredArgsConstructor
public class UserVerificationEmailService {

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;

    @Value("${application.base-url}")
    private String baseUrl;

    public void sendVerificationEmail(String to, String username, String code, String organizationName) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            Context context = new Context();
            context.setVariable("username", username);

            String link = baseUrl + "auth/verify?code=" + code;
            context.setVariable("link", link);

            context.setVariable("orgName", organizationName);

            String htmlContent = templateEngine.process("mail-template", context);
            helper.setText(htmlContent, true);
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