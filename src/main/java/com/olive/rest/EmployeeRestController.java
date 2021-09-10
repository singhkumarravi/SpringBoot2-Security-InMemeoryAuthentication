package com.olive.rest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class EmployeeRestController {

	@GetMapping("/home")
	public String showHome() {
		return "Home";
	}	

	@GetMapping("/common")
	public String showCommon() {
		return "Common";
	}	
	
	@GetMapping("/employee")
	public String showEmp() {
		return "Employee";
	}	

	@GetMapping("/admin")
	public String showAdmin() {
		return "Admin";
	}	
	@GetMapping("/denied")
	public String showDenied() {
		return "Denied";
	}

	@GetMapping("/manager")
	public String showManager() {
		return "Manager";
	}

	@GetMapping("/user")
	public String showUser() {
		return "User";
	}


}
