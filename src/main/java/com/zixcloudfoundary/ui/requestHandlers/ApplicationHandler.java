package com.zixcloudfoundary.ui.requestHandlers;

import java.util.List;

import javax.validation.Valid;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.zixcloudfoundary.models.dataTransferModel.ApplicationDto;
import com.zixcloudfoundary.models.requestModels.RegisterRequestModel;
import com.zixcloudfoundary.models.requestModels.UserLoginRequestModel;
import com.zixcloudfoundary.ui.service.DyamoServiceImpl;

@Controller
@RequestMapping("users")
public class ApplicationHandler {

	private DyamoServiceImpl service;

	/* Default Constructor */
	public ApplicationHandler() {
	}

	/*
	 * Using constructor based dependency Injection to this class.
	 * 
	 * @Param service object of service callback.
	 */
	@Autowired
	public ApplicationHandler(DyamoServiceImpl service) {
		this.service = service;
	}

	@RequestMapping("/")
	public String home() {
		return "index.jsp";
	}

	@ResponseBody
	@RequestMapping("register")
	public ApplicationDto registerUser(@Valid RegisterRequestModel register, BindingResult br) {

		if (br.hasErrors()) {
			List<FieldError> error = br.getFieldErrors();
			for (FieldError err : error) {
				System.out.println(err.getDefaultMessage());
			}
		}
		ModelMapper mapper=new ModelMapper();
		ApplicationDto obj=mapper.map(register, ApplicationDto.class);
		return service.registerUser(obj);
	}
	
	@ResponseBody
	@RequestMapping("service/status")
	public String status()
	{
		return "Accessed protected endpoint after authentication.";
	}
}
