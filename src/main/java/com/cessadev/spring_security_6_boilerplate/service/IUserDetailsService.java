package com.cessadev.spring_security_6_boilerplate.service;

import com.cessadev.spring_security_6_boilerplate.security.CustomUserDetails;

public interface IUserDetailsService {
  CustomUserDetails loadUserByUsername(String email);
}
