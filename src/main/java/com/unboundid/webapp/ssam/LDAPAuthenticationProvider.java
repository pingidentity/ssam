/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.GetAuthorizationEntryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.GetAuthorizationEntryResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RetainIdentityRequestControl;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * This is an authentication provider that uses the LDAP SDK to perform bind
 * operations.
 * 
 * If a searchBindFilter is defined in the SSAMSettings, then the 
 * authentication provider will attempt to search for the user and bind to the
 * entry returned using a simple bind request.
 * Otherwise, the authentication provider will perform a bind using a SASL 
 * PLAIN bind request with an authorization ID constructed with the provided 
 * username.
 * 
 * Each authentication method will create an authentication token using
 * LDAPUser, a class extending Spring Security's User class that accepts a DN
 * in its constructor. Accepting a DN is important for constructing 
 * authorization IDs, which are needed when performing LDAP operations on 
 * behalf of the authenticated user.
 */
public class LDAPAuthenticationProvider implements AuthenticationProvider
{
  @Autowired
  private LDAPConnectionPool pool;

  @Autowired
  private SSAMSettings settings;

  private static final Collection<? extends GrantedAuthority> EMPTY_AUTHORITIES =
          Collections.unmodifiableCollection(new ArrayList<GrantedAuthority>());

  /** {@inheritDoc} */
  @Override
  public Authentication authenticate(Authentication authentication)
          throws AuthenticationException
  {
    String searchBindFilter = settings.getSearchBindFilter();
    User userDetails = null;
    BindRequest request = null;
    
    // Get the username and password, making sure they're not empty
    String username = authentication.getName();
    String password = (String) authentication.getCredentials();
    if(StringUtils.isEmpty(username) || StringUtils.isEmpty(password))
    {
      throw new BadCredentialsException(
              "Username and password must be provided");
    }
   
    // If a filter is available, perform 'Search and Bind'
    if(StringUtils.isNotEmpty(searchBindFilter))
    {
      Entry entry;
      String filter = searchBindFilter.replace("$0", username);
      try
      {
        entry = pool.searchForEntry(settings.getBaseDN(), SearchScope.SUB,
            Filter.create(filter));
        if(entry == null)
        {
          throw new BadCredentialsException("Invalid credentials for user: "
                + username);
        }
      }
      catch(LDAPSearchException e)
      {
        throw new BadCredentialsException("An exception occurred while searching" +
              " for user: " + username, e);
      }
      catch(LDAPException e)
      {
        throw new BadCredentialsException("The filter string cannot be decoded " +
              "as a valid search filter for user: " + username, e);
      }
      
      // Obtain the bind DN and try to bind, retaining the identity of the
      // pooled connection
      request = new SimpleBindRequest(entry.getDN(), password, 
          new RetainIdentityRequestControl());
      
      userDetails = new LDAPUser(entry.getDN(), username, password,
          EMPTY_AUTHORITIES);
    }
    else
    {
      // Construct a SASL PLAIN Bind Request since no filter is available for
      // 'Search and Bind'
      request = new PLAINBindRequest("u:" + username, password,
          new GetAuthorizationEntryRequestControl(false, true, "1.1"),
          new RetainIdentityRequestControl());
    }
    
    try
    {
      BindResult result = pool.bind(request);
      
      // If no DN is available, a PLAIN Bind Request was submitted
      // Use a Response Control to obtain a DN for the authentication token
      if(request instanceof PLAINBindRequest) 
      {
        GetAuthorizationEntryResponseControl responseControl =
            GetAuthorizationEntryResponseControl.get(result);
        
        if (responseControl == null) 
        {
          // No entry returned, User will be used for the authentication token
          userDetails = new User(username, password, EMPTY_AUTHORITIES);
        } 
        else 
        {
          // Entry returned, LDAPUser will be used for the authentication token
          userDetails = new LDAPUser(responseControl.getAuthZEntry().getDN(),
              username, password, EMPTY_AUTHORITIES);
        }
      }
    }
    catch(LDAPException e)
    {
      throw new BadCredentialsException("Invalid credentials for user:  "
              + username, e);
    }

    // Construct the authentication token and return it
    return new UsernamePasswordAuthenticationToken(userDetails, password,
            EMPTY_AUTHORITIES);
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(Class<?> authentication)
  {
    return UsernamePasswordAuthenticationToken.class
            .isAssignableFrom(authentication);
  }
}
