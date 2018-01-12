/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * This class is used for creating authentication tokens in the LDAP 
 * Authentication Provider.
 * 
 * This class accepts a DN, which is important for constructing authzIDs.
 * AuthzIDs are used throughout the application for performing LDAP operations
 * on behalf of the authenticated user, so it is important for the 
 * authentication token to provide a way to obtain the authzID and preventing
 * the possibility of using the wrong prefix, "u: " or "dn: ".
 */
public class LDAPUser extends User {
  private String dn;

  /** Creates a new instance. */
  public LDAPUser(String dn, String username, String password, 
                  Collection<? extends GrantedAuthority> authorities)
  {
    super(username, password, authorities);
    this.dn = dn;
  }

  /** Returns the DN */
  public String getDN()
  {
    return this.dn;
  }

  /** Constructs and returns an authzID */
  public String getAuthzID()
  {
    return dn == null ? "u: " + getUsername() : "dn: " + dn;
  }
}
