package com.cessadev.spring_security_6_boilerplate.model;

import com.cessadev.spring_security_6_boilerplate.model.enums.ERoles;
import jakarta.persistence.Entity;
import lombok.*;

import java.util.Objects;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Role {

  private Long id;
  private ERoles role;

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;
    Role role = (Role) o;
    return Objects.equals(id, role.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }
}
