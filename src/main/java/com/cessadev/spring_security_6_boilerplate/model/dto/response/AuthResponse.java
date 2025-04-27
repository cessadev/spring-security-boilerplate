package com.cessadev.spring_security_6_boilerplate.model.dto.response;

import lombok.*;

import java.util.List;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
  private String token;
  private String username;
  private List<String> roles;
  private long expiresIn;
  private String tokenType = "Bearer";
}
