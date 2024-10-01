import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

@Controller
public class HomeController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/home")
    public String home(Model model, @AuthenticationPrincipal OidcUser oidcUser) {
        model.addAttribute("name", oidcUser.getFullName());
        return "home";
    }

    @GetMapping("/logout-success")
    public String logoutSuccess() {
        return "redirect:/"; // Redirect to index page after logout
    }
}
