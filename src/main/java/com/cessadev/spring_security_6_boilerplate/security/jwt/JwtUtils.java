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

/**
 * Clase utilitaria para manejo de tokens JWT (JSON Web Tokens).
 *
 * Proporciona funcionalidades para:
 * <ul>
 *   <li>Generación de tokens JWT</li>
 *   <li>Validación de tokens</li>
 *   <li>Extracción de información de tokens</li>
 * </ul>
 *
 * Configuración requerida en application.properties:
 * <pre>
 * jwt.secret.key=clave-secreta-en-base64
 * jwt.expiration.time=86400000 # 24 horas en milisegundos
 * jwt.issuer=nombre-de-tu-aplicacion
 * </pre>
 */
@Slf4j
@Component
public class JwtUtils {

  /**
   * Clave secreta para firmar los tokens (en formato Base64)
   */
  @Value("${jwt.secret.key}")
  private String secretKey;

  /**
   * Tiempo de expiración de los tokens en milisegundos
   */
  @Value("${jwt.expiration.time}")
  private Long expirationTime;

  /**
   * Emisor del token (normalmente el nombre de la aplicación)
   */
  @Value("${jwt.issuer}")
  private String issuer;

  /**
   * Transient para serialización
   * Cache de la clave de firma para mejor rendimiento
   */
  private transient SecretKey cachedSigningKey;

  /**
   * Genera un token JWT para un usuario autenticado
   *
   * @param userDetails Detalles del usuario autenticado
   * @return Token JWT firmado que contiene:
   *         - username como subject
   *         - authorities como claim
   *         - issuer, fecha emisión y expiración
   */
  public String generateAccessToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("authorities", userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));

    return buildToken(claims, userDetails.getUsername());
  }

  /**
   * Genera un token JWT con autoridades específicas
   *
   * @param username    Nombre de usuario (subject del token)
   * @param authorities Colección de autoridades/roles
   * @return Token JWT firmado
   */
  public String generateAccessToken(String username, Collection<? extends GrantedAuthority> authorities) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("authorities", authorities.stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));

    return buildToken(claims, username);
  }

  /**
   * Construye el token JWT con los claims proporcionados
   *
   * @param claims  Información adicional a incluir en el token
   * @param subject Subject del token (normalmente el username)
   * @return Token JWT firmado
   */
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

  /**
   * Verifica si un token JWT es válido
   *
   * @param token Token a validar
   * @return true si el token es válido (firma correcta, no expirado, formato válido)
   */
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

  /**
   * Extrae todos los claims (información contenida) de un token
   *
   * @param token Token JWT
   * @return Objeto Claims con toda la información del token
   * @throws JwtException Si el token es inválido
   */
  public Claims extractAllClaims(String token) {
    return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
  }

  /**
   * Obtiene un claim específico del token
   *
   * @param token          Token JWT
   * @param claimsResolver Función para extraer el claim deseado
   * @param <T>            Tipo del claim a retornar
   * @return Valor del claim solicitado
   */
  public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  /**
   * Obtiene el nombre de usuario (subject) del token
   *
   * @param token Token JWT
   * @return Nombre de usuario contenido en el token
   */
  public String getUsernameFromToken(String token) {
    return getClaim(token, Claims::getSubject);
  }

  /**
   * Obtiene los roles/autoridades del token
   *
   * @param token Token JWT
   * @return Lista de roles/autoridades
   */
  @SuppressWarnings("unchecked")
  public List<String> getRolesFromToken(String token) {
    List<?> roles = Collections.singletonList(getClaim(token, claims -> claims.get("authorities")));
    if (roles == null) return Collections.emptyList();
    return roles.stream()
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .toList();
  }

  /**
   * Obtiene la fecha de expiración del token
   *
   * @param token Token JWT
   * @return Fecha de expiración
   */
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

  /**
   * Verifica el tiempo de expiración definido
   *
   * @return el tiempo de expiración en milisegundos
   */
  public long getExpirationTime() {
    return expirationTime;
  }

  /**
   * Verifica si el token ha expirado
   *
   * @param token Token JWT
   * @return true si el token está expirado, false si aún es válido
   */
  public boolean isTokenExpired(String token) {
    final Date expiration = getExpirationDateFromToken(token);
    return expiration.before(new Date());
  }
}
