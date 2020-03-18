package com.zixcloudfoundary.ui.internals.Generators;

import java.io.Serializable;
import java.util.UUID;

import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.IdentifierGenerator;

public class GenericUserIdGenerator implements IdentifierGenerator {

	@Override
	public Serializable generate(SharedSessionContractImplementor session, Object object) throws HibernateException {

		String id= "DU" + UUID.randomUUID().toString().substring(0, 4);
		System.out.println("The generated User ID : " +id);
		return id;
	}

}
