package com.cessadev.spring_security_6_boilerplate.security;

import com.cessadev.spring_security_6_boilerplate.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
public class CustomUserDetails implements UserDetails {

  private final User user;
  private final List<String> roles;
  private final Collection<? extends GrantedAuthority> authorities;

  public CustomUserDetails(User user, List<String> roles) {
    this.user = user;
    this.roles = roles;
    this.authorities = roles.stream()
            .map(role -> new SimpleGrantedAuthority(role))
            .toList();
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return user.getPassword();
  }

  @Override
  public String getUsername() {
    return user.getEmail(); // Asegúrate que email es único en tu sistema
  }

  @Override
  public boolean isAccountNonExpired() {
    return user.isAccountNonExpired();
  }

  @Override
  public boolean isAccountNonLocked() {
    return user.isAccountNonLocked();
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return user.isCredentialsNonExpired();
  }

  @Override
  public boolean isEnabled() {
    return user.isEnabled();
  }
}
