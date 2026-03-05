package com.innowise.apigateway.exception;

import java.io.Serial;

public class ApigatewaySecurityException extends RuntimeException {

  @Serial
  private static final long serialVersionUID = -2165406166982856477L;

  public ApigatewaySecurityException() {
    super("Security parameters are invalid");
  }

  public ApigatewaySecurityException(String message) {
    super(message);
  }

  public ApigatewaySecurityException(String message, Throwable cause) {
    super(message, cause);
  }
}
