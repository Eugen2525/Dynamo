package com.zixcloudfoundary.handlers.error;

import org.hibernate.id.IdentifierGenerationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@EnableWebMvc
@ControllerAdvice
public class ErrorAndExceptionHandlers extends ResponseEntityExceptionHandler{
	
	@ResponseBody
	@Override
	protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers,
			HttpStatus status, WebRequest request) {
		
		return new ResponseEntity<Object>("Not found", HttpStatus.NOT_FOUND);
	}
	
	@ResponseBody
	@ExceptionHandler(IdentifierGenerationException.class)
	protected ResponseEntity<Object> handleIdGenerationException()
	{
		return new ResponseEntity<Object>("Not able to generate user id for this user.", HttpStatus.INTERNAL_SERVER_ERROR);
	}
}
