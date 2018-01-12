/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

/**
 * Contains the settings for the Self-Service Account Manager application that
 * can be supplied via properties files, system properties, etc.
 */
@Component
@ConfigurationProperties
public class SSAMSettings
{
  private Resource ldapConnectionDetailsResource;
  private int numConnections;
  private String baseDN;
  private String[] objectClasses;
  private String namingAttribute;
  private String recoverPasswordSearchFilter;
  private String version;
  private String messageSubject;
  private String fullTextBeforeToken;
  private String fullTextAfterToken;
  private String compactTextBeforeToken;
  private String compactTextAfterToken;
  private String recaptchaSiteKey;
  private String recaptchaSecretKey;
  private String searchBindFilter;
  private int numberOfInputs;
  private boolean allowSelfServiceDelete;
  private String pingFederateLogoutURL;
  private String pingAccessLogoutURL;
  private String homeURL;

  /** Returns the LDAP Connection Details resource, a Spring resource.
   * There are multiple ways of specifying a resource path. The default
   * path is "classpath:/ssam-ldap-connection-details.json," but can vary from a file
   * path (file:///foo/ssam-ldap-connection-details.json) to a
   * URL (http://example.com/ssam-ldap-connection-details.json).
   */
  public Resource getLdapConnectionDetailsResource()
  {
    return ldapConnectionDetailsResource;
  }

  /** Sets the LDAP Connection Details resource, a Spring resource. */
  public void setLdapConnectionDetailsResource(
          Resource ldapConnectionDetailsResource)
  {
    this.ldapConnectionDetailsResource = ldapConnectionDetailsResource;
  }

  /** Returns the number of LDAP connections to use in the connection pool. */
  public int getNumConnections()
  {
    return numConnections;
  }

  /** Sets the number of LDAP connections to use in the connection pool. */
  public void setNumConnections(int numConnections)
  {
    this.numConnections = numConnections;
  }

  /** Returns the base DN under which user entries are located. */
  public String getBaseDN()
  {
    return baseDN;
  }

  /** Sets the base DN under which user entries are located. */
  public void setBaseDN(String baseDN)
  {
    this.baseDN = baseDN;
  }

  /** Returns the object classes to use when creating user entries. */
  public String[] getObjectClasses()
  {
    return objectClasses;
  }

  /** Sets the object class to use when creating user entries. */
  public void setObjectClasses(String[] objectClasses)
  {
    this.objectClasses = objectClasses;
  }

  /** Returns the RDN attribute of user entries. */
  public String getNamingAttribute()
  {
    return namingAttribute;
  }

  /** Sets the RDN attribute of user entries. */
  public void setNamingAttribute(String namingAttribute)
  {
    this.namingAttribute = namingAttribute;
  }

  /** Returns the version number. */
  public String getVersion()
  {
    return version;
  }

  /** Sets the version number. */
  public void setVersion(String version)
  {
    this.version = version;
  }

  /** Returns the registration code subject message. */
  public String getMessageSubject()
  {
    return messageSubject;
  }

  /** Sets the registration code subject message. */
  public void setMessageSubject(String messageSubject)
  {
    this.messageSubject = messageSubject;
  }

  /** Returns the full registration code preceding text. */
  public String getFullTextBeforeToken()
  {
    return fullTextBeforeToken;
  }

  /** Sets the full registration code preceding text. */
  public void setFullTextBeforeToken(String fullTextBeforeToken)
  {
    this.fullTextBeforeToken = fullTextBeforeToken;
  }

  /** Returns the full registration code succeeding text. */
  public String getFullTextAfterToken()
  {
    return fullTextAfterToken;
  }

  /** Sets the full registration code succeeding text. */
  public void setFullTextAfterToken(String fullTextAfterToken)
  {
    this.fullTextAfterToken = fullTextAfterToken;
  }

  /** Returns the compact registration code preceding text. */
  public String getCompactTextBeforeToken()
  {
    return compactTextBeforeToken;
  }

  /** Sets the compact registration code succeeding text. */
  public void setCompactTextBeforeToken(String compactTextBeforeToken)
  {
    this.compactTextBeforeToken = compactTextBeforeToken;
  }

  /** Returns the compact registration code preceding text. */
  public String getCompactTextAfterToken()
  {
    return compactTextAfterToken;
  }

  /** Sets the compact registration code succeeding text. */
  public void setCompactTextAfterToken(String compactTextAfterToken)
  {
    this.compactTextAfterToken = compactTextAfterToken;
  }

  /** Returns the reCAPTCHA site key. */
  public String getRecaptchaSiteKey()
  {
    return recaptchaSiteKey;
  }

  /** Sets the reCAPTCHA site key. */
  public void setRecaptchaSiteKey(String recaptchaSiteKey)
  {
    this.recaptchaSiteKey = recaptchaSiteKey;
  }

  /** Returns the reCAPTCHA secret key. */
  public String getRecaptchaSecretKey()
  {
    return recaptchaSecretKey;
  }

  /** Sets the reCAPTCHA secret key. */
  public void setRecaptchaSecretKey(String recaptchaSecretKey)
  {
    this.recaptchaSecretKey = recaptchaSecretKey;
  }

  /** Returns whether to allow self-service delete. */
  public boolean isSelfServiceDeleteEnabled()
  {
    return allowSelfServiceDelete;
  }

  /** Sets whether to allow self-service delete. */
  public void setAllowSelfServiceDelete(boolean allowSelfServiceDelete)
  {
    this.allowSelfServiceDelete = allowSelfServiceDelete;
  }

  /** Checks if reCAPTCHA is available. */
  public boolean isRecaptchaEnabled()
  {
    return StringUtils.isNotEmpty(recaptchaSecretKey)
            && StringUtils.isNotEmpty(recaptchaSiteKey);
  }

  /**
   * Returns the LDAP search filter used when the password recovery flow
   * searches for the account to recover. The value provided in the UI will be
   * substituted for occurrences of "$0".
   */
  public String getRecoverPasswordSearchFilter()
  {
    return recoverPasswordSearchFilter;
  }

  /**
   * Sets the LDAP search filter used when the password recovery flow searches
   * for the account to recover. The value provided in the UI will be
   * substituted for occurrences of "$0".
   */
  public void setRecoverPasswordSearchFilter(String recoverPasswordSearchFilter)
  {
    this.recoverPasswordSearchFilter = recoverPasswordSearchFilter;
  }

  /** Checks whether the registration code uses a single input. */
  public boolean isSingleInputEnabled()
  {
    return numberOfInputs <= 1;
  }

  /** Gets the number of inputs desired for the registration code. */
  public int getNumberOfInputs()
  {
    return numberOfInputs;
  }
  
  /** Sets the number of inputs desired for the registration code. */
  public void setNumberOfInputs(int numberOfInputs)
  {
    this.numberOfInputs = numberOfInputs;
  }

  /** Returns the LDAP search filter used during the authentication process. */
  public String getSearchBindFilter()
  {
    return searchBindFilter;
  }

  /** Sets the LDAP search filter used during the authentication process. */
  public void setSearchBindFilter(String searchBindFilter)
  {
    this.searchBindFilter = searchBindFilter;
  }

  /** Returns the URL used for the PingFederate logout process. */
  public String getPingFederateLogoutURL()
  {
    return pingFederateLogoutURL;
  }

  /** Sets the URL used for the PingFederate logout process. */
  public void setPingFederateLogoutURL(String pingFederateLogoutURL)
  {
    this.pingFederateLogoutURL = pingFederateLogoutURL;
  }

  /** Returns the URL used for the PingAccess logout process. */
  public String getPingAccessLogoutURL()
  {
    return pingAccessLogoutURL;
  }

  /** Sets the URL used for the PingAccess logout process. */
  public void setPingAccessLogoutURL(String pingAccessLogoutURL)
  {
    this.pingAccessLogoutURL = pingAccessLogoutURL;
  }

  /** Returns the URL for the home navigation menu item. */
  public String getHomeURL()
  {
    return homeURL;
  }

  /** Sets the URL for the home navigation menu item. */
  public void setHomeURL(String homeURL)
  {
    this.homeURL = homeURL;
  }
  
  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
  }
}
