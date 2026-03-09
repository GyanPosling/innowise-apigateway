package com.innowise.apigateway.controller.api;

import com.innowise.apigateway.exception.ErrorResponse;
import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

@Hidden
public interface FallbackControllerApi {

  Mono<ResponseEntity<ErrorResponse>> fallback();
}
