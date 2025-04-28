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

/**
 * Filtro personalizado para autenticación JWT.
 * <p>
 * Este filtro intercepta las solicitudes de login (/api/auth/login), valida las credenciales
 * y genera un token JWT si la autenticación es exitosa.
 * <p>
 * Extiende UsernamePasswordAuthenticationFilter de Spring Security.
 */
@Component
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final JwtUtils jwtUtils;
  private final ObjectMapper objectMapper;

  /**
   * Constructor del filtro
   *
   * @param jwtUtils Utilidades para manejo de JWT
   * @param authenticationManager Gestor de autenticación de Spring
   * @param objectMapper Para serialización/deserialización JSON
   */
  public JwtAuthenticationFilter(JwtUtils jwtUtils,
                                 AuthenticationManager authenticationManager,
                                 ObjectMapper objectMapper) {
    this.jwtUtils = jwtUtils;
    this.objectMapper = objectMapper;
    super.setAuthenticationManager(authenticationManager);
    super.setFilterProcessesUrl("/api/auth/login"); // Endpoint configurable
  }

  /**
   * Intenta autenticar al usuario con las credenciales proporcionadas
   *
   * @param request Solicitud HTTP
   * @param response Respuesta HTTP
   * @return Authentication objeto si es exitoso
   * @throws AuthenticationServiceException Si hay errores en el formato de la solicitud
   */
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
                                              HttpServletResponse response) throws AuthenticationException {
    try {
      /* Validaciones de método y content-type */
      if (!request.getMethod().equals("POST")) {
        throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
      }

      if (!MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(request.getContentType())) {
        throw new AuthenticationServiceException("Invalid content type. Expected application/json");
      }

      /* Deserializa el cuerpo de la solicitud */
      AuthRequest authRequest = objectMapper.readValue(request.getInputStream(), AuthRequest.class);

      /* Crea el token de autenticación */
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
              authRequest.getEmail(),
              authRequest.getPassword()
      );

      return this.getAuthenticationManager().authenticate(authenticationToken);
    } catch (IOException e) {
      throw new AuthenticationServiceException("Error parsing authentication request", e);
    }
  }

  /**
   * Maneja la autenticación exitosa generando un JWT
   *
   * @param request Solicitud HTTP
   * @param response Respuesta HTTP
   * @param chain Filtro chain
   * @param authResult Resultado de la autenticación
   */
  @Override
  protected void successfulAuthentication(HttpServletRequest request,
                                          HttpServletResponse response,
                                          FilterChain chain,
                                          Authentication authResult) throws IOException {

    /* Extrae información del usuario autenticado */
    String username = authResult.getName();
    String authorities = authResult.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

    /* Genera el token JWT */
    String token = jwtUtils.generateAccessToken(username, authResult.getAuthorities());

    /* Construye la respuesta */
    Map<String, Object> httpResponse = new HashMap<>();
    httpResponse.put("status", HttpStatus.OK.value());
    httpResponse.put("token", token);
    httpResponse.put("username", username);
    httpResponse.put("roles", authorities);
    httpResponse.put("message", "Authentication successful");
    httpResponse.put("expires_in", jwtUtils.getExpirationTime() / 1000); // En segundos

    /* Configura la respuesta HTTP */
    response.setHeader("Authorization", "Bearer " + token);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.getWriter().write(objectMapper.writeValueAsString(httpResponse));
    response.setStatus(HttpStatus.OK.value());
  }

  /**
   * Maneja errores de autenticación
   *
   * @param request Solicitud HTTP
   * @param response Respuesta HTTP
   * @param failed Excepción de autenticación
   */
  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            AuthenticationException failed) throws IOException {

    /* Configura la respuesta HTTP */
    Map<String, Object> errorResponse = new HashMap<>();
    errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());
    errorResponse.put("error", "Authentication failed");
    errorResponse.put("message", failed.getMessage());
    errorResponse.put("path", request.getRequestURI());

    /* Construye respuesta de error */
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
  }
}
