/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import java.io.File;
import java.io.InputStream;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.Banner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;

import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.util.json.LDAPConnectionDetailsJSONSpecification;

/**
 * The is the main Self-Service Account Manager Spring Boot application class 
 * that defines the application configuration.
 */
@SpringBootApplication
public class SSAMApplication extends SpringBootServletInitializer
        implements ServletContextListener
{
  @Autowired
  private SSAMSettings settings;

  static final String[] UNAUTHENTICATED_PATHS = { "/register",
          "/verifyRegistrationCode", "/resendRegistrationCode", "/initPassword",
          "/recoverPassword", "/resetPassword", "/fonts/**" };

  /**
   * The default constructor is used to set the {@code spring.config.location}
   * system property when running within a PingData server.  The SSAM
   * installer writes out a customized {@code application.properties} file under
   * the server's {@code webapps/ssam-config} directory, which is what SSAM
   * should use, if it exists.
   */
  public SSAMApplication()
  {
    // If the application is running within a PingData server, an
    // INSTANCE_ROOT environment variable will be set, so set the
    // "spring.config.location" system property to the location of that file.
    String instanceRoot = System.getenv("INSTANCE_ROOT")
      .replace("/", File.separator);
    if (instanceRoot != null)
    {
      String relativePath = "webapps/ssam-config/application.properties"
        .replace("/", File.separator);
      File applicationProperties = new File(instanceRoot, relativePath);
      if (applicationProperties.exists())
      {
        System.setProperty("spring.config.location",
          applicationProperties.getAbsolutePath());
      }
    }
  }

  /** Runs the stand-alone SSAM application. */
  public static void main(String[] args)
  {
    if(args.length > 0 && args[0].equalsIgnoreCase("install"))
    {
      SSAMInstaller.main(args);
    }
    else
    {
      new SpringApplicationBuilder(SSAMApplication.class)
              .bannerMode(Banner.Mode.OFF).run(args);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected SpringApplicationBuilder configure(
          SpringApplicationBuilder application)
  {
    // Register the Spring Boot application so that the web application is
    // configured appropriately when launched by the servlet container. This is
    // needed when creating a Spring Boot deployable war.
    return application.sources(SSAMApplication.class).bannerMode(Banner.Mode.OFF);
  }

  /**
   * Returns an LDAP connection pool bean that can be wired into other
   * components, and will be closed when destroyed.
   *
   * @return The connection pool is returned
   *
   * @throws Exception
   *           Thrown if there is a problem creating the pool
   */
  @Bean(destroyMethod = "close")
  public LDAPConnectionPool ldapConnectionPool() throws Exception
  {
    try (InputStream is = settings.getLdapConnectionDetailsResource().getInputStream())
    {
      LDAPConnectionDetailsJSONSpecification connectionDetails =
              LDAPConnectionDetailsJSONSpecification.fromInputStream(is);
      return connectionDetails.createConnectionPool(
              settings.getNumConnections(), settings.getNumConnections());
    }
  }


  /**
   * The following empty interface implementation methods are needed for
   * ServletContext initialization in some web application servers.
   */

  /**
   * {@inheritDoc}
   */
  @Override
  public void contextInitialized(ServletContextEvent event)
  {
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void contextDestroyed(ServletContextEvent event)
  {
  }
}
