/*
 * Copyright 2014-2017 Ping Identity Corporation
 * All Rights Reserved.
 */

package com.unboundid.webapp.ssam;

import org.springframework.stereotype.Component;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

@Component
public class HTTPRequestParameterFilter implements javax.servlet.Filter {
  public FilterConfig filterConfig;

  public void doFilter(final ServletRequest request,
    final ServletResponse response, FilterChain chain)
    throws java.io.IOException, javax.servlet.ServletException {

    String curMethod = ((HttpServletRequest) request).getMethod();
    //only allow for GET and POST requests.
    if (curMethod.equalsIgnoreCase("get") || curMethod.equalsIgnoreCase("post"))
    {
      chain.doFilter(request, response);
    }
  }

  public void init(final FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }
  public void destroy() {}
}