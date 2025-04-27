package com.cessadev.spring_security_6_boilerplate.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.cessadev.spring_security_6_boilerplate.security.jwt.JwtUtils;
import com.cessadev.spring_security_6_boilerplate.model.dto.request.AuthRequest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final JwtUtils jwtUtils;
  private final ObjectMapper objectMapper;

  public JwtAuthenticationFilter(JwtUtils jwtUtils,
                                 AuthenticationManager authenticationManager,
                                 ObjectMapper objectMapper) {
    this.jwtUtils = jwtUtils;
    this.objectMapper = objectMapper;
    super.setAuthenticationManager(authenticationManager);
    super.setFilterProcessesUrl("/api/auth/login"); // Endpoint configurable
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
                                              HttpServletResponse response) throws AuthenticationException {
    try {
      if (!request.getMethod().equals("POST")) {
        throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
      }

      if (!MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(request.getContentType())) {
        throw new AuthenticationServiceException("Invalid content type. Expected application/json");
      }

      AuthRequest authRequest = objectMapper.readValue(request.getInputStream(), AuthRequest.class);

      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
              authRequest.getEmail(),
              authRequest.getPassword()
      );

      return this.getAuthenticationManager().authenticate(authenticationToken);
    } catch (IOException e) {
      throw new AuthenticationServiceException("Error parsing authentication request", e);
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request,
                                          HttpServletResponse response,
                                          FilterChain chain,
                                          Authentication authResult) throws IOException {
    String username = authResult.getName();
    String authorities = authResult.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

    String token = jwtUtils.generateAccessToken(username, authResult.getAuthorities());

    Map<String, Object> httpResponse = new HashMap<>();
    httpResponse.put("status", HttpStatus.OK.value());
    httpResponse.put("token", token);
    httpResponse.put("username", username);
    httpResponse.put("roles", authorities);
    httpResponse.put("message", "Authentication successful");
    httpResponse.put("expires_in", jwtUtils.getExpirationTime() / 1000); // En segundos

    response.setHeader("Authorization", "Bearer " + token);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.getWriter().write(objectMapper.writeValueAsString(httpResponse));
    response.setStatus(HttpStatus.OK.value());
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            AuthenticationException failed) throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    Map<String, Object> errorResponse = new HashMap<>();
    errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());
    errorResponse.put("error", "Authentication failed");
    errorResponse.put("message", failed.getMessage());
    errorResponse.put("path", request.getRequestURI());

    response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
  }
}
