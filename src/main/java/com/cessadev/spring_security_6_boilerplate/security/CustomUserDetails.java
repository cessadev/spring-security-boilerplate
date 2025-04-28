package com.cessadev.spring_security_6_boilerplate.security;

import com.cessadev.spring_security_6_boilerplate.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Implementación personalizada de UserDetails que envuelve la entidad User.
 *
 * Proporciona la adaptación entre la entidad User del dominio y los requerimientos
 * de Spring Security para la autenticación.
 */
@Getter
public class CustomUserDetails implements UserDetails {

  /**
   * Entidad User del dominio
   */
  private final User user;

  /**
   * Lista de roles como Strings
   */
  private final List<String> roles;

  /**
   * Colección de autoridades para Spring Security
   */
  private final Collection<? extends GrantedAuthority> authorities;

  /**
   * Constructor principal
   *
   * @param user Entidad User del dominio
   * @param roles Lista de nombres de roles (ej. ["ROLE_ADMIN", "ROLE_USER", "ROLE_INVITED"])
   */
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
