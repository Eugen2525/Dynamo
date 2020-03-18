package com.zixcloudfoundary.models.requestModels;

import javax.validation.constraints.NotBlank;

public class UserLoginRequestModel {

	@NotBlank(message = "User ID can't be blank.")
	private String userid;
	@NotBlank(message = "Please Enter your password.")
	private String password;

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUserid() {
		return userid;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

}
