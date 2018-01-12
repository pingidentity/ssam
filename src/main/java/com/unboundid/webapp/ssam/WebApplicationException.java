/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Encapsulates information about web application exceptions, which can be
 * converted to response entities using {@link #toResponseEntity()}.
 */
public class WebApplicationException
        extends Exception
{
  private static final long serialVersionUID = 5238824513472966622L;

  private HttpStatus statusCode;

  /**
   * Creates a new instance using the specified HTTP status code and error
   * message.
   */
  public WebApplicationException(HttpStatus statusCode, String message)
  {
    super(message);
    this.statusCode = statusCode;
  }

  /** Converts the exception to an HTTP response entity. */
  public ResponseEntity<String> toResponseEntity()
  {
    return new ResponseEntity<>(getMessage(), statusCode);
  }
}
