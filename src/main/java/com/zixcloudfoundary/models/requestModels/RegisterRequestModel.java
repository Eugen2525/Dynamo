package com.zixcloudfoundary.models.requestModels;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class RegisterRequestModel {

	@NotBlank
	@Size(min = 3, message = "First name shouldn't be less than 3 charactes.")
	private String first_name;

	@NotBlank
	@Size(min = 3, message = "Last Name shouldn't be less than 3 characters.")
	private String last_name;

	@NotBlank
	@Size(min = 10, max = 10, message = "Phone number should be of 10 digits.")
	private String number;

	@Email(message = "Please Enter a valid email.")
	private String email;

	@NotBlank
	@Pattern(regexp = "((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})\n"
			+ "", message = "Password must be min of 6 chars and"
					+ "uppercase and lowercase chars with a special char and number.")
	private String password;

	@NotBlank(message = "Mandotary Field.")
	private String city;

	@NotBlank(message = "Mandotary Field.")
	private String state;

	@NotBlank(message = "Mandotary Field.")
	private String country;

	public String getFirst_name() {
		return first_name;
	}

	public void setFirst_name(String first_name) {
		this.first_name = first_name;
	}

	public String getLast_name() {
		return last_name;
	}

	public void setLast_name(String last_name) {
		this.last_name = last_name;
	}

	public String getNumber() {
		return number;
	}

	public void setNumber(String number) {
		this.number = number;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	@Override
	public String toString() {
		return "RegisterRequestModel [first_name=" + first_name + ", last_name=" + last_name + ", number=" + number
				+ ", email=" + email + ", password=" + password + ", city=" + city + ", state=" + state + ", country="
				+ country + "]";
	}
}
