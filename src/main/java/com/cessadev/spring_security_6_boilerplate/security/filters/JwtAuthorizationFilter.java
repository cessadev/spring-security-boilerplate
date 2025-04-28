package com.cessadev.spring_security_6_boilerplate.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.cessadev.spring_security_6_boilerplate.security.jwt.JwtUtils;
import com.cessadev.spring_security_6_boilerplate.service.impl.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Filtro que verifica y valida tokens JWT en las solicitudes.
 * <p>
 * Este filtro se ejecuta en cada request y verifica:
 * <ul>
 *   <li>Presencia del header Authorization</li>
 *   <li>Formato correcto del token (Bearer)</li>
 *   <li>Validez del token JWT</li>
 *   <li>Correspondencia entre el token y el usuario</li>
 * </ul>
 * <p>
 * Si la validación es exitosa, establece la autenticación en el SecurityContext.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private static final String AUTH_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";

  private final JwtUtils jwtUtils;
  private final UserDetailsServiceImpl userDetailsService;
  private final ObjectMapper objectMapper;

  /**
   * Método principal que procesa cada request
   */
  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest request,
                                  @NonNull HttpServletResponse response,
                                  @NonNull FilterChain filterChain) throws IOException {
    try {
      processTokenAuthentication(request);
      filterChain.doFilter(request, response);
    } catch (Exception e) {
      handleAuthenticationError(response, e);
    }
  }

  /**
   * Procesa el token de autenticación del header
   */
  private void processTokenAuthentication(HttpServletRequest request) {
    String authHeader = request.getHeader(AUTH_HEADER);

    if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
      return; // No hay token, sigue la cadena de filtros
    }

    if (SecurityContextHolder.getContext().getAuthentication() != null) {
      log.warn("Security context already contains authentication");
      return;
    }

    String token = authHeader.substring(BEARER_PREFIX.length());
    authenticateWithToken(token);
  }

  /**
   * Autentica al usuario usando el token JWT
   */
  private void authenticateWithToken(String token) {
    if (!jwtUtils.isValidToken(token)) {
      throw new JwtAuthenticationException("Invalid JWT token");
    }

    String username = jwtUtils.getUsernameFromToken(token);
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

    validateTokenMatchesUser(token, userDetails);

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            userDetails,
            null, // Credenciales (no necesarias después de autenticado)
            userDetails.getAuthorities()
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);
    log.debug("Authenticated user: {}", username);
  }

  /**
   * Valida que el token corresponda al usuario
   */
  private void validateTokenMatchesUser(String token, UserDetails userDetails) {
    if (!jwtUtils.getUsernameFromToken(token).equals(userDetails.getUsername())) {
      throw new JwtAuthenticationException("Token does not match user credentials");
    }
  }

  /**
   * Maneja errores de autenticación
   */
  private void handleAuthenticationError(HttpServletResponse response, Exception ex) throws IOException {
    log.error("JWT Authentication error: {}", ex.getMessage());

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    Map<String, String> errorDetails = Map.of(
            "error", "Unauthorized",
            "message", ex.getMessage(),
            "reason", resolveErrorReason(ex)
    );

    objectMapper.writeValue(response.getWriter(), errorDetails);
  }

  /**
   * Determina la razón del error para la respuesta
   */
  private String resolveErrorReason(Exception ex) {
    if (ex instanceof UsernameNotFoundException) {
      return "user-not-found";
    }
    if (ex instanceof JwtAuthenticationException) {
      return "invalid-token";
    }
    return "authentication-failed";
  }

  /**
   * Excepción personalizada para errores JWT
   */
  private static class JwtAuthenticationException extends RuntimeException {
    public JwtAuthenticationException(String message) {
      super(message);
    }
  }
}
