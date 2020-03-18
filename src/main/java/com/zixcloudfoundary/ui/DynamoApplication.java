package com.zixcloudfoundary.ui;

import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class DynamoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DynamoApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder createObject() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public ModelMapper mapper() {
		return new ModelMapper();
	}
}
