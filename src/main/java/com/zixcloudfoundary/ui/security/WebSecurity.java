package com.zixcloudfoundary.ui.security;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.zixcloudfoundary.ui.service.DynamoService;

@EnableWebSecurity
@Configuration
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private Environment env;
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	private DynamoService userDetailServiceProvider;

	@Autowired
	public WebSecurity(Environment env, BCryptPasswordEncoder bCryptPasswordEncoder,
			DynamoService userDetailServiceProvider) {
		this.env = env;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.userDetailServiceProvider = userDetailServiceProvider;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		
		http.authorizeRequests().antMatchers("/css/**", "/js/**", "/images/**", "/users/").permitAll()
				.and().authorizeRequests()
				.antMatchers(HttpMethod.POST, env.getProperty("user.login.url"), env.getProperty("user.register.url"))
				.permitAll().anyRequest().authenticated().and()
				.addFilter(getAuthenticationFilter());
	}

	private Filter getAuthenticationFilter() throws Exception {
		AuthenticationFilter filter = new AuthenticationFilter(authenticationManager(), env, userDetailServiceProvider);
		filter.setFilterProcessesUrl(env.getProperty("filter.processing.url"));
		return filter;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailServiceProvider).passwordEncoder(bCryptPasswordEncoder);
	}

}
