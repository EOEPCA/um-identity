package um.identity;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import um.identity.customers.Customer;
import um.identity.customers.CustomerDAO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.Principal;

@org.springframework.stereotype.Controller
public class Controller {

	private final CustomerDAO customerDAO;

	public Controller(CustomerDAO customerDAO) {
		this.customerDAO = customerDAO;
	}

	@GetMapping(path = "/")
	public String index() {
		return "external";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpSession session) throws Exception {
		request.logout();
		session.invalidate();
		return "redirect:/";
	}

	@GetMapping(path = "/customers")
	public String customers(Principal principal, Model model) {
		Iterable<Customer> customers = customerDAO.findAll();
		model.addAttribute("customers", customers);
		model.addAttribute("username", principal.getName());
		return "customers";
	}

}