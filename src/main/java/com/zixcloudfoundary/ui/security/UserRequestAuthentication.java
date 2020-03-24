package com.zixcloudfoundary.ui.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Jwts;

public class UserRequestAuthentication extends OncePerRequestFilter {

	private Environment env;

	private static Logger log = LoggerFactory.getLogger(UserRequestAuthentication.class);

	@Autowired
	public UserRequestAuthentication(Environment env) {
		this.env = env;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authorizationheader = request.getHeader(env.getProperty("authorization.token.header.name"));
		log.info("Authorization header from the reuqest " + authorizationheader.toString());

		if (authorizationheader == null
				|| !authorizationheader.startsWith(env.getProperty("authorization.header.prefix"))) {
			filterChain.doFilter(request, response);
			return;
		}
		UsernamePasswordAuthenticationToken authentication = getUsernamePasswordAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		filterChain.doFilter(request, response);

	}

	private UsernamePasswordAuthenticationToken getUsernamePasswordAuthentication(HttpServletRequest request) {
		String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));

		if (authorizationHeader == null) {
			log.error("The Authorization header is Null.");
			return null;
		}

		String token = authorizationHeader.replace(env.getProperty("authorization.header.prefix"), "");
		String userId = Jwts.parser()
				.setSigningKey(env.getProperty("token.secret"))
				.parseClaimsJws(token)
				.getBody().getSubject();
		
		if (userId == null) {
			log.error("User ID is null.");
			return null;
		}

		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}

}
