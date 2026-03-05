package com.innowise.apigateway.security;

import com.innowise.apigateway.exception.ApigatewaySecurityException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  private static final String BEARER_PREFIX = "Bearer ";
  private static final String LOGIN_PATH = "/api/v1/auth/login";
  private static final String REGISTER_PATH = "/api/v1/auth/register";

  @Value("${jwt.secret:}")
  private String secret;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String path = exchange.getRequest().getPath().value();
    if (LOGIN_PATH.equals(path) || REGISTER_PATH.equals(path)) {
      return chain.filter(exchange);
    }

    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
      throw new JwtException("Unauthorized");
    }

    String token = authHeader.substring(BEARER_PREFIX.length());
    Claims claims = parseClaims(token);
    if (claims == null) {
      throw new JwtException("Unauthorized");
    }

    ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();
    applyHeader(requestBuilder, "X-USER-ID", claims.get("userId"));
    applyHeader(requestBuilder, "X-USER-ROLE", claims.get("role"));
    applyHeader(requestBuilder, "X-USER-EMAIL", claims.get("email"));
    applyHeader(requestBuilder, "X-USER-NAME", claims.getSubject());
    ServerHttpRequest mutatedRequest = requestBuilder.build();

    return chain.filter(exchange.mutate().request(mutatedRequest).build());
  }

  @Override
  public int getOrder() {
    return -1;
  }

  private Claims parseClaims(String token) {
    if (secret == null || secret.isBlank()) {
      throw new ApigatewaySecurityException();
    }

    try {
      return Jwts.parserBuilder()
          .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
          .build()
          .parseClaimsJws(token)
          .getBody();
    } catch (JwtException | IllegalArgumentException ex) {
      return null;
    }
  }

  private void applyHeader(ServerHttpRequest.Builder builder, String name, Object value) {
    if (value != null) {
      builder.header(name, String.valueOf(value));
    }
  }

}
