/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import static com.unboundid.webapp.ssam.SSAMApplication.UNAUTHENTICATED_PATHS;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;

/**
 * This is a Ping security configuration that can be enabled using the
 * "ping-authentication" profile. This assumes that PingFederate/PingAccess are
 * configured to take care of authentication, and that the principal information
 * is provided in an HTTP header.
 */
@Configuration
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@Profile("ping-authentication")
public class PingSecurityConfiguration
        extends WebSecurityConfigurerAdapter
{
  /** {@inheritDoc} */
  @Override
  protected void configure(HttpSecurity http) throws Exception
  {
    // add a request header pre-authentication filter to the filter chain to
    // perform header-based authorization
    http.addFilterBefore(preAuthenticationFilter(), CsrfFilter.class)
            .exceptionHandling().accessDeniedPage("/error").and()
            .authorizeRequests()
            // allow unauthenticated access to the following
            .antMatchers(UNAUTHENTICATED_PATHS)
            .permitAll()
            // require authenticated access to everything else
            .anyRequest().authenticated()
            .and().logout().logoutSuccessUrl("/");
  }

  /** {@inheritDoc} */
  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception
  {
    // use a pre-authenticated authentication provider
    PreAuthenticatedAuthenticationProvider authenticationProvider =
            new PreAuthenticatedAuthenticationProvider();
    authenticationProvider.setPreAuthenticatedUserDetailsService(
            new PreAuthenticatedGrantedAuthoritiesUserDetailsService());
    auth.authenticationProvider(authenticationProvider);
  }

  /**
   * Returns a request header authentication filter that can be used for the
   * pre-authentication scenario. This will use the principal defined in the
   * "PING_USER" request header, and optionally the authorities defined as a
   * comma-separated list of roles in the "PING_AUTHORITIES" request header.
   *
   * @return The filter is returned
   *
   * @throws Exception
   *           Thrown if the authentication manager cannot be built
   */
  @Bean
  public Filter preAuthenticationFilter() throws Exception
  {
    RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter()
    {
      /** {@inheritDoc} */
      @Override
      protected Object getPreAuthenticatedPrincipal(HttpServletRequest request)
      {
        // treat an empty header value as null
        String principal = (String) super.getPreAuthenticatedPrincipal(request);
        return "".equals(principal) ? null : principal;
      }
    };
    filter.setAuthenticationManager(authenticationManager());

    // make sure the "PING_USER" header is provided, and eagerly invalidate
    // sessions if the principal changes
    filter.setExceptionIfHeaderMissing(false);
    filter.setCheckForPrincipalChanges(true);

    // configure the filter to use the "PING_USER" and "PING_AUTHORITIES"
    // headers
    filter.setPrincipalRequestHeader("PING_USER");
    filter.setAuthenticationDetailsSource(new AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails>()
    {
      @Override
      public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(
              HttpServletRequest request)
      {
        String authoritiesHeader = request.getHeader("PING_AUTHORITIES");
        List<GrantedAuthority> authorities = new ArrayList<>();
        if(authoritiesHeader != null && !authoritiesHeader.isEmpty())
        {
          for(String authority : authoritiesHeader.split(","))
          {
            authorities.add(new SimpleGrantedAuthority(authority.trim()));
          }
        }
        return new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
                request, authorities);
      }
    });
    return filter;
  }
}
