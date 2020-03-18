package com.zixcloudfoundary.ui.service;

import java.util.ArrayList;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.zixcloudfoundary.models.dataTransferModel.ApplicationDto;
import com.zixcloudfoundary.ui.data.Entity.UserEntity;
import com.zixcloudfoundary.ui.service.globalRepo.CoreRepository;

@Service
public class DyamoServiceImpl implements DynamoService {

	private CoreRepository dataCallback;
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	private ModelMapper mapper;

	/* Default Constructor */
	public DyamoServiceImpl() {
	}

	@Autowired
	public DyamoServiceImpl(CoreRepository dataCallback, BCryptPasswordEncoder bCryptPasswordEncoder,
			ModelMapper mapper) {
		this.dataCallback = dataCallback;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.mapper = mapper;

	}

	public ApplicationDto registerUser(ApplicationDto obj) {
		obj.setEncryptedPassword(bCryptPasswordEncoder.encode(obj.getPassword()));
		UserEntity entity = mapper.map(obj, UserEntity.class);
		UserEntity updated=dataCallback.save(entity);
		return mapper.map(updated, ApplicationDto.class);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserEntity details = dataCallback.findByuserid(username);
		if (details == null)
			throw new UsernameNotFoundException("Invalid Username or Password.");
		return new User(details.getUserId(), details.getEncryptedPassword(), true, true, true, true, new ArrayList());
	}

}
