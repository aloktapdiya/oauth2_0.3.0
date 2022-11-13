package com.nermink.authorizationserver.config;

import com.nermink.authorizationserver.impl.UserServiceImpl;
import com.nermink.authorizationserver.service.UserService;
import lombok.RequiredArgsConstructor;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final UserServiceImpl userService;

//  @Resource(name = "userService")
//  private UserDetailsService userDetailsService;
  
  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {

    http
        .authorizeRequests()
        .antMatchers("/users/**").permitAll()
        .antMatchers("/clients/**").permitAll()
        .anyRequest().authenticated()
        .and()
        .csrf().ignoringAntMatchers("/users/**", "/clients/**")
        .and()
        .formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    var provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userService);
    provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance()); //temporary
    return new ProviderManager(provider);
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return this.userService;
  }
//  @Autowired
//  public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
//      auth.userDetailsService(userDetailsService)
//              .passwordEncoder(encoder());
//  } 
  
  @Bean
  public BCryptPasswordEncoder encoder() {
      return new BCryptPasswordEncoder();
  }
  @Bean
  public FilterRegistrationBean corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true);
      config.addAllowedOrigin("*");
      config.addAllowedHeader("*");
      config.addAllowedMethod("*");
      source.registerCorsConfiguration("/**", config);
      FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
      bean.setOrder(0);
      return bean;
  }
}
