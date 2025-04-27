package com.cessadev.spring_security_6_boilerplate.persistence.repository;

import com.cessadev.spring_security_6_boilerplate.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByEmail(String email);
}
