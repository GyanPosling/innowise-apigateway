package com.innowise.apigateway.controller;

import com.innowise.apigateway.controller.api.FallbackControllerApi;
import com.innowise.apigateway.exception.ErrorResponse;
import java.time.LocalDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class FallbackController implements FallbackControllerApi {

  // CircuitBreaker forwards the original method, but this handler is read-only and only returns an error payload.
  @RequestMapping(
      path = "/fallback",
      method = {
          RequestMethod.GET,
          RequestMethod.POST,
          RequestMethod.PUT,
          RequestMethod.PATCH,
          RequestMethod.DELETE,
          RequestMethod.OPTIONS,
          RequestMethod.HEAD
      }
  )
  @Override
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
