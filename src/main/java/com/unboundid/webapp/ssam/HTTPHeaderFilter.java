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
import javax.servlet.http.HttpServletResponse;

@Component
public class HTTPHeaderFilter implements javax.servlet.Filter {
    public FilterConfig filterConfig;

    public void doFilter(final ServletRequest request,
                         final ServletResponse response, FilterChain chain)
            throws java.io.IOException, javax.servlet.ServletException {

        HttpServletResponse res = (HttpServletResponse) response;

        // Set this variable to the sha256 pin of your public key
        // This value can be generated using the "openssl" command line tool
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning
        String pinSha256 = "";

        if(pinSha256.length() > 0)
        {
            res.setHeader("Public-Key-Pins", "max-age=518400; " +
                    "pin-sha256=\"" + pinSha256 + "\"; " +
                    "includeSubDomains");
        }

        chain.doFilter(request, response);
    }

    public void init(final FilterConfig filterConfig) { this.filterConfig = filterConfig; }

    public void destroy() {}

}