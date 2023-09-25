package um.identity.customers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping({"/api/customers"})
public class CustomersController {

	private final CustomerDAO customerDAO;

	public CustomersController(CustomerDAO customerDAO) {
		this.customerDAO = customerDAO;
	}

	@GetMapping
	public Iterable<Customer> getCustomers() {
		return customerDAO.findAll();
	}

	@DeleteMapping("/{id}")
	public void deleteCustomer(@PathVariable Long id) {
		customerDAO.deleteById(id);
	}

}