package com.cessadev.spring_security_6_boilerplate.model;

import lombok.*;

import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@ToString(exclude = "password")
@AllArgsConstructor
@NoArgsConstructor
public class User {

  private Long id;
  private String email;
  private String password;

  private boolean enabled = true;
  private boolean accountNonExpired = true;
  private boolean credentialsNonExpired = true;
  private boolean accountNonLocked = true;

  private Set<Role> roles;

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    User user = (User) o;
    return Objects.equals(id, user.id) &&
            Objects.equals(email, user.email);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, email);
  }
}
