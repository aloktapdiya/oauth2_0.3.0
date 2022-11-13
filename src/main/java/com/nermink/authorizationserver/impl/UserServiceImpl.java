package com.nermink.authorizationserver.impl;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.nermink.authorizationserver.domain.model.AppUser;
import com.nermink.authorizationserver.domain.repository.AppUserRepository;
import com.nermink.authorizationserver.dto.request.CreateUserRequest;
import com.nermink.authorizationserver.dto.response.UserResponse;
import com.nermink.authorizationserver.service.UserService;


@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService, UserService {

	
	  @Autowired
	  private AppUserRepository appUserRepository;

	
//    @Autowired
//    private UserDao userDao;

	  
	  @Override
	  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	    return this.appUserRepository.findByUsername(username)
	        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
	  }	  
	  
//    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
//    	Optional<AppUser> user = appUserRepository.findByUsername(userId);
//        if (user == null) {
//            throw new UsernameNotFoundException("Invalid username or password.");
//        }
//        return new org.springframework.security.core.userdetails.User(String.valueOf(user.getId()), user.getPassword(), getAuthority());
//    }

	public UserResponse save(CreateUserRequest request) {
		var user = new AppUser(request.getUsername(), request.getPassword(), List.of());
		this.appUserRepository.save(user);
		return new UserResponse(user);
	}

    private List<SimpleGrantedAuthority> getAuthority() {
        return Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    public List<AppUser> findAll() {
        List<AppUser> list = new ArrayList<>();
        appUserRepository.findAll().iterator().forEachRemaining(list::add);
        return list;
    }

//    @Override
//    public void delete(String id) {
//    	appUserRepository.deleteById(id);
//    }


//	@Override
//	public AppUser save(AppUser user) {
//		// TODO Auto-generated method stub
//		return null;
//	}

	@Override
	public void delete(long id) {
		// TODO Auto-generated method stub
		
	}

//    @Override
//    public AppUser save(AppUser user) {
//        return userDao.save(user);
//    }

}
