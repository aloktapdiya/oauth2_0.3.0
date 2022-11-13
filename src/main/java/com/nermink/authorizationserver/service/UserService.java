package com.nermink.authorizationserver.service;

import java.util.List;

import com.nermink.authorizationserver.domain.model.AppUser;


public interface UserService {

   // AppUser save(AppUser user);

    List<AppUser> findAll();

    void delete(long id);
}
