/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import static com.unboundid.webapp.ssam.SSAMApplication.UNAUTHENTICATED_PATHS;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * This is an LDAP security configuration that can be enabled using the
 * "ldap-authentication" profile. This will perform simple binds against a
 * directory server for authentication, and uses form-based login.
 */
@Configuration
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@Profile("ldap-authentication")
public class LDAPSecurityConfiguration
        extends WebSecurityConfigurerAdapter
{
  @Autowired
  private SSAMSettings settings;

  /** {@inheritDoc} */
  @Override
  protected void configure(HttpSecurity http) throws Exception
  {
    http.exceptionHandling().accessDeniedPage("/login").and()
            .authorizeRequests()
            // allow unauthenticated access to the following
            .antMatchers(UNAUTHENTICATED_PATHS).permitAll()
            // require authenticated access to everything else
            .anyRequest().authenticated().and()
            // ... using form-based login with a custom login template
            .formLogin().loginPage("/login").failureUrl("/login?error")
            .permitAll()
            // redirect to the root path upon logout
            .and().logout().logoutSuccessUrl("/");
  }

  /** {@inheritDoc} */
  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception
  {
    auth.authenticationProvider(authenticationProvider());
  }

  /** Returns the LDAP authentication provider. */
  @Bean
  public LDAPAuthenticationProvider authenticationProvider()
  {
    return new LDAPAuthenticationProvider();
  }
}
