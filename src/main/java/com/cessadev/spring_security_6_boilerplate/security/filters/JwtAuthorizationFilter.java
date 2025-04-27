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

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private static final String AUTH_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";

  private final JwtUtils jwtUtils;
  private final UserDetailsServiceImpl userDetailsService;
  private final ObjectMapper objectMapper;

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

  private void processTokenAuthentication(HttpServletRequest request) {
    String authHeader = request.getHeader(AUTH_HEADER);

    if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
      return;
    }

    if (SecurityContextHolder.getContext().getAuthentication() != null) {
      log.warn("Security context already contains authentication");
      return;
    }

    String token = authHeader.substring(BEARER_PREFIX.length());
    authenticateWithToken(token);
  }

  private void authenticateWithToken(String token) {
    if (!jwtUtils.isValidToken(token)) {
      throw new JwtAuthenticationException("Invalid JWT token");
    }

    String username = jwtUtils.getUsernameFromToken(token);
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

    validateTokenMatchesUser(token, userDetails);

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);
    log.debug("Authenticated user: {}", username);
  }

  private void validateTokenMatchesUser(String token, UserDetails userDetails) {
    if (!jwtUtils.getUsernameFromToken(token).equals(userDetails.getUsername())) {
      throw new JwtAuthenticationException("Token does not match user credentials");
    }
  }

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

  private String resolveErrorReason(Exception ex) {
    if (ex instanceof UsernameNotFoundException) {
      return "user-not-found";
    }
    if (ex instanceof JwtAuthenticationException) {
      return "invalid-token";
    }
    return "authentication-failed";
  }

  private static class JwtAuthenticationException extends RuntimeException {
    public JwtAuthenticationException(String message) {
      super(message);
    }
  }
}
