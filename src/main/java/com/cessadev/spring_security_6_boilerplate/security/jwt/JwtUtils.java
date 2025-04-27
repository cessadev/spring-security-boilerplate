package com.cessadev.spring_security_6_boilerplate.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtUtils {

  @Value("${jwt.secret.key}")
  private String secretKey;

  @Value("${jwt.expiration.time}")
  private Long expirationTime;

  @Value("${jwt.issuer}")
  private String issuer;

  private transient SecretKey cachedSigningKey; // Transient para serialización

  public String generateAccessToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("authorities", userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));

    return buildToken(claims, userDetails.getUsername());
  }

  public String generateAccessToken(String username, Collection<? extends GrantedAuthority> authorities) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("authorities", authorities.stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));

    return buildToken(claims, username);
  }

  private String buildToken(Map<String, Object> claims, String subject) {
    return Jwts.builder()
            .claims(claims)
            .subject(subject)
            .issuer(issuer)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + expirationTime))
            .signWith(getSigningKey(), Jwts.SIG.HS256)
            .compact();
  }

  public boolean isValidToken(String token) {
    try {
      Jwts.parser()
              .verifyWith(getSigningKey())
              .build()
              .parseSignedClaims(token);
      return true;
    } catch (ExpiredJwtException ex) {
      log.error("Token expired: {}", ex.getMessage());
    } catch (UnsupportedJwtException ex) {
      log.error("Unsupported JWT: {}", ex.getMessage());
    } catch (MalformedJwtException ex) {
      log.error("Malformed JWT: {}", ex.getMessage());
    } catch (SignatureException ex) {
      log.error("Invalid signature: {}", ex.getMessage());
    } catch (IllegalArgumentException ex) {
      log.error("Illegal argument: {}", ex.getMessage());
    } catch (JwtException ex) {
      log.error("JWT exception: {}", ex.getMessage());
    }
    return false;
  }

  public Claims extractAllClaims(String token) {
    return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
  }

  public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public String getUsernameFromToken(String token) {
    return getClaim(token, Claims::getSubject);
  }

  @SuppressWarnings("unchecked")
  public List<String> getRolesFromToken(String token) {
    List<?> roles = Collections.singletonList(getClaim(token, claims -> claims.get("authorities")));
    if (roles == null) return Collections.emptyList();
    return roles.stream()
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .toList();
  }

  public Date getExpirationDateFromToken(String token) {
    return getClaim(token, Claims::getExpiration);
  }

  private SecretKey getSigningKey() {
    if (cachedSigningKey == null) {
      byte[] keyBytes = Decoders.BASE64.decode(secretKey);
      cachedSigningKey = Keys.hmacShaKeyFor(keyBytes);
    }
    return cachedSigningKey;
  }

  public long getExpirationTime() {
    return expirationTime;
  }

  public boolean isTokenExpired(String token) {
    final Date expiration = getExpirationDateFromToken(token);
    return expiration.before(new Date());
  }
}
