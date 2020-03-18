package com.zixcloudfoundary.ui.data.Entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(name = "UserDetails")
public class UserEntity {

	@Id
	@GeneratedValue(generator = "userIdGenerator")
	@GenericGenerator(name = "userIdGenerator", strategy = "com.zixcloudfoundary.ui.internals.Generators.GenericUserIdGenerator")
	@Column(name = "userid", length = 10, nullable = false, unique = true)
	private String userid;

	@Column(name = "Firstname", length = 20, nullable = false)
	private String first_name;
	@Column(name = "Lastname", length = 20, nullable = false)
	private String last_name;

	@Column(name = "Phone", length = 10, nullable = false)
	private String number;

	@Column(name = "Email", length = 30, nullable = false, unique = true)
	private String email;

	@Column(name = "encryptedPassword", nullable = false)
	private String encryptedPassword;

	@Column(name = "City", length = 50, nullable = false)
	private String city;
	@Column(name = "State", length = 50, nullable = false)
	private String state;
	@Column(name = "Country", length = 50, nullable = false)
	private String country;

	public String getUserId() {
		return userid;
	}

	public void setUserId(String userId) {
		this.userid = userId;
	}

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

	public String getEncryptedPassword() {
		return encryptedPassword;
	}

	public void setEncryptedPassword(String encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
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

}
