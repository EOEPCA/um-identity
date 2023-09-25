package um.identity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import um.identity.customers.Customer;
import um.identity.customers.CustomerDAO;

@Component
public class Loader implements ApplicationRunner {

	private final CustomerDAO customerDAO;

	@Autowired
	public Loader(CustomerDAO customerDAO) {
		this.customerDAO = customerDAO;
	}

	public void run(ApplicationArguments args) {
		Customer customer1 = new Customer();
		customer1.setAddress("1111 foo blvd");
		customer1.setName("Foo Industries");
		customer1.setServiceRendered("Important services");
		customerDAO.save(customer1);
		Customer customer2 = new Customer();
		customer2.setAddress("2222 bar street");
		customer2.setName("Bar LLP");
		customer2.setServiceRendered("Important services");
		customerDAO.save(customer2);
		Customer customer3 = new Customer();
		customer3.setAddress("33 main street");
		customer3.setName("Big LLC");
		customer3.setServiceRendered("Important services");
		customerDAO.save(customer3);
	}

}