package com.innowise.apigateway.controller;

import com.innowise.apigateway.exception.ErrorResponse;
import java.time.LocalDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class FallbackController {

  @GetMapping("/fallback")
  public Mono<ResponseEntity<ErrorResponse>> fallback() {
    ErrorResponse response = ErrorResponse.builder()
        .timestamp(LocalDateTime.now())
        .status(HttpStatus.SERVICE_UNAVAILABLE.value())
        .error(HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase())
        .message("Service is unavailable")
        .path("/fallback")
        .build();
    return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
  }
}
