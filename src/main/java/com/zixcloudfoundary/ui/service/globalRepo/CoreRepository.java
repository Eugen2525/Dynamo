package com.zixcloudfoundary.ui.service.globalRepo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.zixcloudfoundary.ui.data.Entity.UserEntity;

@Repository
public interface CoreRepository extends JpaRepository<UserEntity, String> {
	UserEntity findByuserid(String userid);
}
