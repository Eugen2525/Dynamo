package com.zixcloudfoundary.ui.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zixcloudfoundary.models.requestModels.UserLoginRequestModel;
import com.zixcloudfoundary.ui.service.DynamoService;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;
	private Environment env;
	private DynamoService userDetailServiceProvider;

	public AuthenticationFilter(AuthenticationManager authenticationManager, Environment env, 
			DynamoService userDetailServiceProvider ) {
		this.setAuthenticationManager(authenticationManager);
		this.authenticationManager = authenticationManager;
		this.env = env;
		this.userDetailServiceProvider=userDetailServiceProvider;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			Map<String, String> params = new HashMap<>();

			Map<String, String[]> parameterMap = request.getParameterMap();
			            parameterMap.forEach((key,value) -> { params.put(key, value[0]); });
			String json = String.format( "{ \"userid\" : \"%s\", \"password\" : \"%s\" }", parameterMap.get("userid")[0], parameterMap.get("password")[0]);
			UserLoginRequestModel creds = new ObjectMapper().readValue(json, UserLoginRequestModel.class);
			
			return getAuthenticationManager().authenticate(
					new UsernamePasswordAuthenticationToken(creds.getUserid(), creds.getPassword(), new ArrayList<>()));

		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		/*
		 * Once the user authenticated successfully we will go ahead and generate a web
		 * token to use throughout the session
		 */
		String username = ((User) authResult.getPrincipal()).getUsername();
		String userId = userDetailServiceProvider.loadUserByUsername(username).getUsername();
		String token = Jwts.builder().setSubject(userId)
				.setExpiration(new Date(
						System.currentTimeMillis() + Long.parseLong(env.getProperty("token.ExpMillis"))))
				.signWith(SignatureAlgorithm.HS512, env.getProperty("token.secret")).compact();
		response.addHeader("token", token);
		response.addHeader("userId", userId);

	}

}
