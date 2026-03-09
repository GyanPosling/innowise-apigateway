package com.innowise.apigateway.security;

import com.innowise.apigateway.exception.ApigatewaySecurityException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  private static final String BEARER_PREFIX = "Bearer ";
  private static final String SIGN_ALGORITHM = "HmacSHA256";
  private static final String USER_ID_HEADER = "X-USER-ID";
  private static final String USER_ROLE_HEADER = "X-USER-ROLE";
  private static final String USER_EMAIL_HEADER = "X-USER-EMAIL";
  private static final String USERNAME_HEADER = "X-USER-NAME";
  private static final String TS_HEADER = "X-TS";
  private static final String SIGN_HEADER = "X-SIGN";

  @Value("${jwt.secret:}")
  private String secret;

  @Value("${gateway.internal-signing-secret}")
  private String internalSecret;

  @Value("${security.auth.login-path:/api/v1/auth/login}")
  private String loginPath;

  @Value("${security.auth.register-path:/api/v1/auth/register}")
  private String registerPath;

  private static final List<String> PUBLIC_PATH_PREFIXES = List.of(
      "/swagger-ui",
      "/v3/api-docs",
      "/actuator/health"
  );

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String requestPath = exchange.getRequest().getPath().value();
    if (shouldSkipAuth(requestPath)) {
      return chain.filter(exchange);
    }

    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
      throw new JwtException("Unauthorized");
    }

    String token = authHeader.substring(BEARER_PREFIX.length());
    Claims claims = parseClaims(token).orElseThrow(() -> new JwtException("Unauthorized"));
    String tokenType = claims.get("tokenType", String.class);
    if (!"ACCESS".equals(tokenType)) {
      throw new JwtException("Unauthorized");
    }

    String ts = String.valueOf(Instant.now().getEpochSecond());
    String method = exchange.getRequest().getMethod().name();
    String signature = sign(buildPayload(claims, method, requestPath, ts));
    ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();
    applyHeader(requestBuilder, USER_ID_HEADER, claims.get("userId"));
    applyHeader(requestBuilder, USER_ROLE_HEADER, claims.get("role"));
    applyHeader(requestBuilder, USER_EMAIL_HEADER, claims.get("email"));
    applyHeader(requestBuilder, USERNAME_HEADER, claims.getSubject());
    applyHeader(requestBuilder, TS_HEADER, ts);
    applyHeader(requestBuilder, SIGN_HEADER, signature);
    ServerHttpRequest mutatedRequest = requestBuilder.build();

    return chain.filter(exchange.mutate().request(mutatedRequest).build());
  }

  @Override
  public int getOrder() {
    return -1;
  }

  private boolean shouldSkipAuth(String requestPath) {
    if (loginPath.equals(requestPath) || registerPath.equals(requestPath)) {
      return true;
    }
    return PUBLIC_PATH_PREFIXES.stream().anyMatch(requestPath::startsWith);
  }

  private Optional<Claims> parseClaims(String token) {
    if (secret == null || secret.isBlank()) {
      throw new ApigatewaySecurityException();
    }

    try {
      return Optional.of(
          Jwts.parserBuilder()
              .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
              .build()
              .parseClaimsJws(token)
              .getBody()
      );
    } catch (JwtException | IllegalArgumentException ex) {
      return Optional.empty();
    }
  }

  private void applyHeader(ServerHttpRequest.Builder builder, String name, Object value) {
    if (value != null) {
      builder.header(name, String.valueOf(value));
    }
  }

  private String buildPayload(Claims claims, String method, String path, String ts) {
    return String.join(
        "|",
        normalize(method),
        normalize(path),
        normalize(claims.get("userId")),
        normalize(claims.get("role")),
        normalize(claims.get("email")),
        normalize(claims.getSubject()),
        ts
    );
  }

  private String normalize(Object value) {
    return Objects.toString(value, "");
  }

  private String sign(String payload) {
    if (internalSecret == null || internalSecret.isBlank()) {
      throw new ApigatewaySecurityException();
    }
    try {
      Mac mac = Mac.getInstance(SIGN_ALGORITHM);
      mac.init(new SecretKeySpec(internalSecret.getBytes(StandardCharsets.UTF_8), SIGN_ALGORITHM));
      byte[] result = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(result);
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new ApigatewaySecurityException();
    }
  }

}
