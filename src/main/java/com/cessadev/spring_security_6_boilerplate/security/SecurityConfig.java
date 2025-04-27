package com.cessadev.spring_security_6_boilerplate.security;

import com.cessadev.spring_security_6_boilerplate.security.filters.JwtAuthenticationFilter;
import com.cessadev.spring_security_6_boilerplate.security.filters.JwtAuthorizationFilter;
import com.cessadev.spring_security_6_boilerplate.security.jwt.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtUtils jwtUtils;
  private final UserDetailsService userDetailsService;
  private final JwtAuthorizationFilter jwtAuthorizationFilter;
  private final Environment env; // Maneja perfiles
  private final ObjectMapper objectMapper;

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(
            jwtUtils,
            authenticationManager(http),
            objectMapper
    );
    jwtAuthenticationFilter.setFilterProcessesUrl("/api/auth/login");

    return http
            .cors(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> {
              // Endpoints públicos
              auth.requestMatchers(
                      "/api/auth/**",
                      "/v3/api-docs/**",
                      "/swagger-ui/**",
                      "/swagger-ui.html"
              ).permitAll();

              // Endpoints que requieren autenticación
              auth.anyRequest().authenticated();
            })
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex ->
                    ex.authenticationEntryPoint(authenticationEntryPoint()))
            .addFilter(jwtAuthenticationFilter)
            .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);
    authenticationManagerBuilder
            .userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());
    return authenticationManagerBuilder.build();
  }

  @Bean
  AuthenticationEntryPoint authenticationEntryPoint() {
    return (request, response, authException) -> {
      log.error("Authentication error: {}", authException.getMessage());
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      Map<String, String> error = Map.of(
              "error", "Unauthorized",
              "message", authException.getMessage(),
              "path", request.getRequestURI()
      );
      response.getWriter().write(new ObjectMapper().writeValueAsString(error));
    };
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Configuración para desarrollo y producción
    if (Arrays.asList(env.getActiveProfiles()).contains("dev")) {
      configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:4200"));
      configuration.setAllowedMethods(List.of("*"));
      log.warn("Configuración CORS en modo desarrollo - Permitido todo para localhost");
    } else {
      configuration.setAllowedOrigins(List.of("https://yourproductiondomain.com"));
      configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    }

    configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
