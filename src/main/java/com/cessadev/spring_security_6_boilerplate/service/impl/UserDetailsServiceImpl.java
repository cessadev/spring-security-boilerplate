package com.cessadev.spring_security_6_boilerplate.service.impl;

import com.cessadev.spring_security_6_boilerplate.model.User;
import com.cessadev.spring_security_6_boilerplate.persistence.repository.UserRepository;
import com.cessadev.spring_security_6_boilerplate.security.CustomUserDetails;
import com.cessadev.spring_security_6_boilerplate.service.IUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Servicio que carga los detalles del usuario desde la base de datos.
 *
 * Implementa la interfaz UserDetailsService de Spring Security para integrarse
 * con el proceso de autenticación e implementa la interfaz IUserDetailsService
 * crear un contrato con métodos definido.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserDetailsServiceImpl implements UserDetailsService, IUserDetailsService {

  private final UserRepository userRepository;

  /**
   * Carga un usuario por su email y construye el UserDetails
   *
   * @param email Email del usuario a buscar
   * @return CustomUserDetails con la información del usuario
   * @throws UsernameNotFoundException Si el usuario no existe o está deshabilitado
   */
  @Override
  public CustomUserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    log.debug("Loading user by email: {}", email);

    User user = userRepository.findByEmail(email)
            .orElseThrow(() -> {
              log.error("User not found with email: {}", email);
              return new UsernameNotFoundException("User not found with email: " + email);
            });

    if (!user.isEnabled()) {
      log.warn("User {} is disabled", email);
      throw new UsernameNotFoundException("User is disabled");
    }

    Set<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getRole()))
            .collect(Collectors.toSet());

    log.debug("User {} loaded successfully with {} roles", email, authorities.size());

    return new CustomUserDetails(
            user,
            authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList())
    );
  }
}
