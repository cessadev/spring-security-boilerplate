package com.cessadev.spring_security_6_boilerplate.model.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class AuthRequest {
  @NotBlank
  @Email
  private String email;

  @NotBlank
  private String password;
}
