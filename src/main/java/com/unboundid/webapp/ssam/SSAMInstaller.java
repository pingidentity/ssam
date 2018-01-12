/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;


/**
 * Installs the SSAM application to a Directory or Proxy Server.  During
 * initialization, this tool will determine the hosting server's type, and
 * whether it has enough permanent generation memory set aside.  It will then
 * install the schema, create the SSAM User account, generate SSAM
 * configuration files, perform necessary configuration, and initiate
 * re-indexing.
 */
public class SSAMInstaller extends CommandLineTool
{

  /**
   * Class for runtime installer errors.
   */
  private static class InstallerException extends RuntimeException
  {

    private ResultCode code = ResultCode.LOCAL_ERROR;



    /**
     * Creates a parameterized instance whose return code will be LOCAL_ERROR.
     *
     * @param message error.
     */
    public InstallerException(String message)
    {
      super(message);
    }



    /**
     * Creates a parameterized instance.
     *
     * @param message error.
     * @param code    return code.
     */
    public InstallerException(String message, ResultCode code)
    {
      super(message);
      this.code = code;
    }



    /**
     * Creates a parameterized instance whose return code will be LOCAL_ERROR.
     *
     * @param message error.
     * @param cause   of the error.
     */
    public InstallerException(String message, Throwable cause)
    {
      super(message, cause);
    }



    /**
     * Creates a parameterized instance.
     *
     * @param message error.
     * @param cause   of the error.
     * @param code    return code
     */
    public InstallerException(String message, Throwable cause, ResultCode code)
    {
      super(message, cause);
      this.code = code;
    }



    /**
     * Code that will be used as the this sessions exist code.
     *
     * @return code to return when finished.
     */
    public ResultCode getCode()
    {
      return code;
    }
  }


  // For use in passing the permissive modify control as an array.
  private static final Control[] PERMISSIVE_MODIFY_CONTROL = new Control[]{new PermissiveModifyRequestControl()};



  /**
   * Runs the installer.
   *
   * @param args from command-line input.
   */
  public static void main(String[] args)
  {
    if (args.length == 0)
    {
      System.out.println("Usage: SSAMInstall install");
    }
    String[] trueArgs = new String[args.length - 1];
    System.arraycopy(args, 1, trueArgs, 0, trueArgs.length);
    int ret = new SSAMInstaller().runTool(trueArgs).intValue();
    System.exit(ret);
  }


  //////////////////////////////////////////////////////////////////////////////
  //                                                                          //
  // Names of files in the source directory.                                  //
  //                                                                          //
  //////////////////////////////////////////////////////////////////////////////

  // Name of the SSAM application war file.
  private static final String WAR_FILE_NAME = "ssam.war";

  // Name of the file where SSAM's password is written.  The file will appear
  // in both SSAM's configuration directory as well as written to the resource
  // directory during deployments involving a Proxy Server.
  public static final String SSAM_PIN = "ssam.pin";

  // Name of the SSAM schema file.
  private static final String SSAM_SCHEMA_FILE = "20-unboundid-extended.ldif";

  // Generated dsconfig script for configuring SSAM access to the Directory Server.
  private static final String SSAM_DS_DSCONFIG = "ssam-ds.dsconfig";

  // Generated dsconfig script for configuring hosting of SSAM by the server.
  private static final String SSAM_DEPLOY_DSCONFIG = "ssam-deploy.dsconfig";



  //////////////////////////////////////////////////////////////////////////////
  //                                                                          //
  // Required arguments.                                                      //
  //                                                                          //
  //////////////////////////////////////////////////////////////////////////////

  private FileArgument serverRootArg;

  private IntegerArgument ldapPortArg;

  private DNArgument bindDNArg;

  private StringArgument bindPasswordArg;

  private DNArgument peopleBaseDNArg;

  private StringArgument smtpServerHostnameArg;

  private StringArgument smtpSenderEmailAddressArg;


  //////////////////////////////////////////////////////////////////////////////
  //                                                                          //
  // Optional arguments.                                                      //
  //                                                                          //
  //////////////////////////////////////////////////////////////////////////////

  private BooleanArgument useSSLArg;

  private BooleanArgument useStartTLSArg;

  private FileArgument trustStorePathArg;

  private BooleanArgument trustAllArg;

  private DNArgument ssamUserDNArg;

  private StringArgument ssamUserPasswordArg;

  private FileArgument ssamUserPasswordFileArg;

  private BooleanArgument resetSSAMUserPasswordArg;

  private StringArgument smtpServerUsernameArg;

  private StringArgument smtpServerPasswordArg;

  // Optional site key used for the Google reCAPTCHA human verification.
  private StringArgument reCaptchaSiteKeyArg;

  // The secret key used for the Google reCAPTCHA human verification.
  private StringArgument reCaptchaSecretKeyArg;

  // The URL used for logging out of PingFederate. If deploying SSAM with Ping,
  // must not be empty. Note that the full URL must be used.
  // For example: https://<hostname>:<PingFederatePort>/ext/logout
  private StringArgument pingFederateLogoutURLArg;

  // The URL used for logging out of PingAccess. If deploying SSAM with Ping,
  // must not be empty. Note that the full URL must be used.
  // For example: https://<hostname>/pa/oidc/logout
  private StringArgument pingAccessLogoutURLArg;

  // Indicates stack traces should be included in error messages during this
  // tool's session.
  private BooleanArgument debugArg;

  // Whether or not to actually deploy SSAM for use in installations involving
  // the Proxy Server.  Use this when configuring a backend Directory Server,
  // without actually deploying SSAM.
  private BooleanArgument noDeployArg;


  //////////////////////////////////////////////////////////////////////////////
  //                                                                          //
  // Environment variables, initialized during initialization.                //
  //                                                                          //
  //////////////////////////////////////////////////////////////////////////////

  // LDAP connection for updating schema etc.
  private LDAPConnection ldapConnection;

  // Output log for this class, in the resources directory.
  private File logFile;

  // Log file output stream.
  private PrintWriter logOutput;

  // Directory from which the installer is running.
  private File sourceDir;

  // Directory to which generated dsconfig batch scripts and logs are added.
  private File resourceDir;

  // Directory under the server root where the SSAM war will be placed.
  private File webAppsDir;

  // Directory under the server root where SSAM can find its config files.
  private File ssamConfigDir;

  // Schema modifications to be applied to the server for installing the schema.
  private List<Modification> schemaMods;

  // Name of the local host that will be used to configure SSAM client communication.
  private String localHostName;

  // Port number of the server's HTTPS Connection Handler.
  private Integer httpsPort;

  // DN of the SSAM User, that will be installed under the base DN.
  private DN ssamUserDN;

  // Password for the SSAM User, that is either generated or user-specified.
  private String ssamUserPassword;

  // File containing the SSAM User password.
  private File ssamUserPasswordResourceFile;

  // File containing the SSAM User password.
  private File ssamUserPasswordConfigFile;

  // Base DN under which the SSAM User is created, and under which the people
  // base DN exists with user entries.
  private String baseDN;

  // Indicates whether the server is a Directory Server, in which case
  // the server will be configured for OTP delivery support.
  private boolean isDirectoryServer;

  // Indicates the password was read from an existing resource pin file.
  private boolean passwordFromResourcePINFile;



  /**
   * {@inheritDoc}
   */
  @Override
  public void addToolArguments(ArgumentParser argumentParser)
          throws ArgumentException
  {
    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Required arguments.                                                    //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    serverRootArg = new FileArgument(null, "serverRoot", true, 1, "[directory]",
            "Absolute or relative path to the server to host SSAM, or path to a" +
            " Directory Server whose tools will be used to configure a backend server" +
            " server for SSAM access.", true, true, false, true);
    argumentParser.addArgument(serverRootArg);

    ldapPortArg = new IntegerArgument('p', "ldapPort", true, 1, "[port]",
            "LDAP or LDAPS port for communicating with the server.");
    argumentParser.addArgument(ldapPortArg);

    bindDNArg = new DNArgument('D', "bindDN", true, 1, "[dn]",
            "DN of an account used to manage the server's configuration.");
    argumentParser.addArgument(bindDNArg);

    bindPasswordArg = new StringArgument('w', "bindPassword", true, 1, "[password]",
            "Password of the account used to manage the server's configuration.");
    argumentParser.addArgument(bindPasswordArg);

    peopleBaseDNArg = new DNArgument(null, "peopleBaseDN", true, 1, "[dn]",
            "The pre-configured server base DN for user entries.");
    argumentParser.addArgument(peopleBaseDNArg);


    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // SMTP arguments.                                               //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    // Required when configuring SSAM access.
    smtpServerHostnameArg = new StringArgument(null, "smtpServerHostname", true,
            1, "[hostname]", "Name of the SMTP host used to deliver email notifications.");
    argumentParser.addArgument(smtpServerHostnameArg);

    // Required when configuring SSAM access.
    smtpSenderEmailAddressArg = new StringArgument(null,
            "smtpSenderEmailAddress", true, 1, "[email address]",
            "Email address used as the sender, when notifying users.");
    argumentParser.addArgument(smtpSenderEmailAddressArg);

    smtpServerUsernameArg = new StringArgument(null, "smtpServerUsername", false, 1, "[username]",
            "Username of the SMTP server account, if required by the SMTP server.");
    argumentParser.addArgument(smtpServerUsernameArg);

    smtpServerPasswordArg = new StringArgument(null, "smtpServerPassword", false, 1, "[password]",
            "Password of the SMTP server account, if required by the SMTP server.");
    argumentParser.addArgument(smtpServerPasswordArg);

    // SMTP username and password must be specified together.
    argumentParser.addDependentArgumentSet(smtpServerUsernameArg, smtpServerPasswordArg);
    argumentParser.addDependentArgumentSet(smtpServerPasswordArg, smtpServerUsernameArg);


    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Optional connection arguments.                                         //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    useSSLArg = new BooleanArgument('Z', "useSSL",
            "Specifies use of SSL to secure communication with the server by" +
            " this tool, and also for SSAM.");
    argumentParser.addArgument(useSSLArg);

    useStartTLSArg = new BooleanArgument('q', "useStartTLS",
            "Use StartTLS to secure communication with the server by this tool," +
            " and also for SSAM.");
    argumentParser.addArgument(useStartTLSArg);

    trustAllArg = new BooleanArgument('X', "trustAll",
            "Trust all server SSL certificates.");
    argumentParser.addArgument(trustAllArg);

    trustStorePathArg = new FileArgument('P', "trustStorePath", false, 1, "[file]",
            "Path to the keystore used to establish trust between this tool" +
            " and the server.  You can use /server-root/config/keystore.",
            true, true, true, false);
    argumentParser.addArgument(trustStorePathArg);

    ssamUserDNArg = new DNArgument(null, "ssamUserDN", false, 1, "[dn]",
            "DN of SSAM user account used to bind to the server.");
    argumentParser.addArgument(ssamUserDNArg);
    // Hidden for now until credentials management support is addressed.
    ssamUserDNArg.setHidden(true);

    ssamUserPasswordArg = new StringArgument(null, "ssamUserPassword", false, 1, "[password]",
            "Password for the SSAM user. If not specified in this option, nor " +
            "in a password file, a password will be generated if the SSAM user account " +
            "does not already exist.");
    // todo: add to argument description later for proxy support
    // "A specified password is required for Proxy installs."
    argumentParser.addArgument(ssamUserPasswordArg);

    ssamUserPasswordFileArg = new FileArgument(null, "ssamUserPasswordFile", false, 1, "[file]",
            "Path to the SSAM user password file.",
            true, true, true, false);
    // todo: add to argument description later for proxy support-- ", required for Proxy installs"
    argumentParser.addArgument(ssamUserPasswordFileArg);

    // Hidden for now to obfuscate passwords being written to files in clear-text,
    // since a generated password looks less like a password than a generated one.
    ssamUserPasswordArg.setHidden(true);
    ssamUserPasswordFileArg.setHidden(true);
    argumentParser.addExclusiveArgumentSet(ssamUserPasswordArg, ssamUserPasswordFileArg);

    resetSSAMUserPasswordArg = new BooleanArgument(null, "resetSSAMUserPassword",
            "Force a password reset of the SSAM user account if the SSAM user DN entry exists. " +
            "Not recommended if the SSAM user account is replicated, because the same password " +
            "must be used in all installations, instead the correct user password or the pin " +
            "file should be obtained from another server.");
    argumentParser.addArgument(resetSSAMUserPasswordArg);

    // SSL method and trust arguments are exclusive.
    argumentParser.addExclusiveArgumentSet(useSSLArg, useStartTLSArg);

    // If using StartTLS or SSL, if a trust store path is not specified,
    // a trust-all trust manager will be used by this tool and configured
    // for SSAM.
    argumentParser.addExclusiveArgumentSet(trustAllArg, trustStorePathArg);

    // The user must specify a trust argument if using SSL.
    argumentParser.addDependentArgumentSet(useSSLArg, trustAllArg, trustStorePathArg);
    argumentParser.addDependentArgumentSet(useStartTLSArg, trustAllArg, trustStorePathArg);


    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Optional reCAPTCHA arguments.                                          //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    // Optional site key used for the Google reCAPTCHA human verification.
    reCaptchaSiteKeyArg = new StringArgument(null, "reCaptchaSiteKey", false, 1, "[key]",
            "Optional site key used for the Google reCAPTCHA human verification.");
    argumentParser.addArgument(reCaptchaSiteKeyArg);

    // The secret key used for the Google reCAPTCHA human verification. May be empty.
    reCaptchaSecretKeyArg = new StringArgument(null, "reCaptchaSecretKey", false, 1, "[key]",
            "Optional secret key used for the Google reCAPTCHA human verification.");
    argumentParser.addArgument(reCaptchaSecretKeyArg);

    // Both must be specified, or neither.
    argumentParser.addDependentArgumentSet(reCaptchaSiteKeyArg, reCaptchaSecretKeyArg);
    argumentParser.addDependentArgumentSet(reCaptchaSecretKeyArg, reCaptchaSiteKeyArg);


    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Optional Ping arguments.                                               //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    pingAccessLogoutURLArg = new StringArgument(null, "pingAccessLogoutURL", false, 1, "[url]",
            "Optional URL used for logging out of PingAccess, for example https://<hostname>/pa/oidc/logout." +
            " Required if deploying SSAM with Ping. Note that the full URL must be used.");
    argumentParser.addArgument(pingAccessLogoutURLArg);

    pingFederateLogoutURLArg = new StringArgument(null, "pingFederateLogoutURL", false, 1, "[url]",
            "optional URL used for logging out of PingFederate, for example https://<hostname>:<PingFederatePort>/ext/logout." +
            " Required if deploying SSAM with Ping. Note that the full URL must be used.");
    argumentParser.addArgument(pingFederateLogoutURLArg);

    // Both must be specified, or neither.
    argumentParser.addDependentArgumentSet(pingAccessLogoutURLArg, pingFederateLogoutURLArg);
    argumentParser.addDependentArgumentSet(pingFederateLogoutURLArg, pingAccessLogoutURLArg);


    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Miscellaneous optional arguments.                                      //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    noDeployArg = new BooleanArgument(null, "noDeploy",
            "Indicates that the server will be configured for" +
            " SSAM access, but SSAM will not be deployed on the server.");
    argumentParser.addArgument(noDeployArg);

    debugArg = new BooleanArgument(null, "debug",
            "Debug this installer application.");
    argumentParser.addArgument(debugArg);
    debugArg.setHidden(true);
  }



  /**
   * Main installer logic.
   *
   * @return exit code.
   */
  @Override
  public ResultCode doToolProcessing()
  {
    try
    {
      // Validate user input and collect information about the server,
      // initializing environmental variables.  If this fails, nothing will
      // have changed in the server or the filesystem besides creation of the
      // resource directory, initialization of this tool's log, and generation
      // of the SSAM user password file.
      initialize();

      // Deploy the password file, WAR and configuration files.
      deployFiles();

      // Adds the SSAM user when configuring a Directory Server.
      provisionSSAMUser();

      // Configure the server for access by SSAM, and/or for hosting SSAM.
      configureServer();

      // Cleanup and report any further info to the user.
      finish();

      return ResultCode.SUCCESS;
    }
    catch (Exception e)
    {
      System.out.println("Error");

      System.err.println();
      if (debugArg.isPresent())
      {
        e.printStackTrace(System.err);
      }
      else
      {
        System.err.println(e.getLocalizedMessage());
      }

      return e instanceof InstallerException ?
              ((InstallerException)e).getCode() : ResultCode.LOCAL_ERROR;
    }
    finally
    {
      if (ldapConnection != null)
      {
        ldapConnection.close();
      }

      LOG("Finished");

      if (logOutput != null)
      {
        logOutput.close();
      }
    }
  }



  /**
   * Creates an instance.
   */
  private SSAMInstaller()
  {
    super(System.out, System.err);
  }



  /**
   * Perform any preliminary initialization and server checks before starting
   * configuration steps.  After initialization, this tool will do everything
   * it can to ensure configuration steps succeed.
   *
   * This method does not make any changes to the server, but does create the
   * resource directory so that logging to the log file is possible.
   */
  private void initialize() throws IOException
  {

    // Determine the location of the exploded ZIP directory.
    final String scriptDirPath = System.getenv("SCRIPT_DIR");
    if (scriptDirPath == null)
    {
      throw new InstallerException("SCRIPT_DIR is not defined");
    }
    sourceDir = new File(scriptDirPath);

    // Create a directory to put generated files and log of this session.
    resourceDir = new File(sourceDir, "resource");
    if (!resourceDir.exists() && !resourceDir.mkdirs())
    {
      throw new InstallerException("Failed to create resource directory " +
              resourceDir.getCanonicalPath() + ".");
    }


    // Make sure the files expected in the ZIP package are present.
    final File schemaFile = new File(sourceDir, SSAM_SCHEMA_FILE);
    if (!schemaFile.exists())
    {
      throw new InstallerException("Schema file " +
              schemaFile.getCanonicalPath() + " does not exist.");
    }
    final File warFile = new File(sourceDir, WAR_FILE_NAME);
    if (!schemaFile.exists())
    {
      throw new InstallerException("WAR file " +
              warFile.getCanonicalPath() + " does not exist.");
    }


    // Delete an older log file if necessary.
    logFile = new File(resourceDir, "log");
    if (logFile.exists() && !logFile.delete())
    {
      throw new InstallerException("Failed to delete existing log file " +
              logFile.getCanonicalPath() + ".");
    }


    // Initialize a new log file.
    try
    {
      if (!logFile.createNewFile())
      {
        throw new InstallerException("Failed to create log file " +
                logFile.getCanonicalPath() + ".");
      }
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Failed to create log file " +
              logFile.getCanonicalPath() + ".", ioe);
    }
    try
    {
      logOutput = new PrintWriter(logFile);
      LOG("Log initialized");
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Failed to create log output stream.", ioe);
    }


    File serverRoot = serverRootArg.getValue().getCanonicalFile();
    int ldapPort    = ldapPortArg.getValue();

    // Do sanity checking to make sure the server root looks like a server root.
    final String dsConfigPath = StaticUtils.isWindows() ? "bat\\dsconfig.bat" : "bin/dsconfig";
    final File dsconfig = new File(serverRoot, dsConfigPath);
    if (!dsconfig.exists())
    {
      throw new InstallerException("Directory " + serverRoot.getPath() +
              " is not the root of a Ping server.");
    }

    System.out.println("Server Root: " + serverRoot);
    System.out.println();
    System.out.print("Initializing ..... ");


    // Ensure the current user is the same as that used to setup the server.
    // This is important since the installer will be copying files into the
    // server root and must be accessible by the server.
    final File serverUserFile = new File(serverRoot, "config/server.user");
    if (!serverUserFile.exists())
    {
      throw new InstallerException(
              "File " + serverUserFile + " does not exist" +
                      " or is inaccessible.  The server does not appear to have" +
                      " been setup or is being run by a user that cannot access the" +
                      " server root.  First run setup before invoking this script" +
                      " rerunning this script as the same user that was used to" +
                      " setup the server.");
    }
    try (FileInputStream fis = new FileInputStream(serverUserFile))
    {
      Properties p = new Properties();
      p.load(fis);
      String serverUser = p.getProperty("server.user");
      String currentUser = System.getProperty("user.name");
      if (!serverUser.equals(currentUser))
      {
        throw new InstallerException(
                "This script must be run as user " + serverUser + ".",
                ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
      }
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Failed to read " + serverUserFile.getPath(),
              ioe, ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }


    // Read the name of the server that was established during setup.  This
    // will by used when configuring SSAM client access to the server.
    final File serverHostFile = new File(serverRoot, "config/server.host");
    if (!serverHostFile.exists())
    {
      throw new InstallerException(
              "File " + serverHostFile + " does not exist" +
                      " or is inaccessible.  The server does not appear to have" +
                      " been setup or is being run by a user that cannot access the" +
                      " server root.  First run setup before invoking this script" +
                      " and rerun this script as the same user that was used to" +
                      " setup the server.");
    }
    try (FileInputStream fis = new FileInputStream(serverHostFile))
    {
      Properties p = new Properties();
      p.load(fis);
      localHostName = p.getProperty("hostname");
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Failed to read " + serverHostFile.getPath(),
              ioe, ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }


    // Do a few sanity checks that the specified LDAP port appears to be one
    // on which the server specified by it server root is listening.
    final File configLDIF = new File(serverRoot, "config/config.ldif");
    try
    {
      String file = new String(Files.readAllBytes(configLDIF.toPath()));
      if (!file.contains("ds-cfg-listen-port: " + ldapPort))
      {
        throw new InstallerException("The server at " + serverRoot.getPath() +
                " is not listening on port " + ldapPort);
      }
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Failed to read " + configLDIF, ioe);
    }
    final File serverLock = new File(serverRoot, "locks/server.lock");
    if (!serverLock.exists())
    {
      throw new InstallerException("The server at " + serverRoot + " does" +
              " not appear to be running.");
    }


    // Connect to the local server to determine its type and any other information.
    try
    {
      ldapConnection = setUpSecureConnection(ldapPort);

      ldapConnection.bind(bindDNArg.getValue().toString(), bindPasswordArg.getValue());

      SearchResultEntry rootDSE = ldapConnection.getEntry("", "vendorVersion",
              "namingContexts");
      if (rootDSE != null)
      {
        // Determine whether the server is a Directory Server or Proxy Server.
        String value = rootDSE.getAttributeValue("vendorVersion");
        if (!value.contains("UnboundID") && !value.contains("Ping"))
        {
          throw new InstallerException("Server is not a Ping server");
        }
        if (value.contains("Broker") || value.contains("Metrics") || value.contains("Sync"))
        {
          throw new InstallerException("Servers of type " + value +
                  " are not supported.");
        }

        if (!value.contains("Proxy"))
        {
          isDirectoryServer = true;
        }

        // Basic SMTP server info is required unless we are just doing a Proxy deploy.
        if (isDirectoryServer &&
                (! smtpServerHostnameArg.isPresent() || ! smtpSenderEmailAddressArg.isPresent()))
        {
          throw new InstallerException("When configuring a Directory Server for SSAM access, you must" +
                  " supply values for both the --" + smtpServerUsernameArg.getLongIdentifier() +
                  " and --" + smtpSenderEmailAddressArg.getLongIdentifier() + " options.");
        }

        // Determine what the baseDN should be by determining the baseDN of the
        // backend hosting the people base DN subtree.  The base DN must be a
        // parent of the base where users are stored.
        String peopleBaseDN = peopleBaseDNArg.getValue().toString();
        String[] namingContexts = rootDSE.getAttributeValues("namingContexts");
        if (namingContexts != null)
        {
          for (String namingContext : namingContexts)
          {
            if (DN.isAncestorOf(namingContext, peopleBaseDN, true))
            {
              baseDN = namingContext;
              break;
            }
          }
          if (baseDN == null)
          {
            throw new InstallerException("According to its root DSE, " +
                    localHostName + ":" + ldapPort + " does not host any" +
                    " naming contexts (base DNs) that are ancestors of " +
                    peopleBaseDN + "(found " +
                    Arrays.toString(namingContexts) + "). You must specify" +
                    " a value for --" + peopleBaseDNArg.getLongIdentifier() +
                    " that is subordinate to an existing base DN.");
          }
        }
        else
        {
          throw new InstallerException(
                  "Could not determine the naming contexts from the Root DSE");
        }


        // If we are going to be deploying SSAM, make sure the HTTPS Connection
        // Handler has been enabled.
        if (deploySSAM())
        {
          SearchResultEntry e = ldapConnection.getEntry(
                  "cn=HTTPS Connection Handler,cn=Connection Handlers,cn=config",
                  "ds-cfg-enabled", "ds-cfg-listen-port");
          if (e == null)
          {
            throw new InstallerException(
                    "The HTTPS Connection Handler was not found in the server's configuration.");
          }
          if (!e.getAttributeValueAsBoolean("ds-cfg-enabled"))
          {
            throw new InstallerException(
                    "The HTTPS Connection Handler is not enabled" +
                            " in the server's configuration.  Enable the Handler and rerun" +
                            " this tool.");
          }
          httpsPort = e.getAttributeValueAsInteger("ds-cfg-listen-port");
        }
      }
      else
      {
        throw new InstallerException(
                "Failed to determine product information from the root DSE entry.");
      }

      // Determine necessary updates to the schema.
      final Schema serverSchema = Schema.getSchema(ldapConnection);
      final Schema ssamSchema;
      final File ssamSchemaFile = new File(sourceDir, SSAM_SCHEMA_FILE);
      try
      {
        ssamSchema = Schema.getSchema(ssamSchemaFile);
      }
      catch (Exception ioe)
      {
        throw new InstallerException(
                "Failed to read SSAM schema from " + ssamSchemaFile, ioe);
      }
      schemaMods = diffSchemas(serverSchema, ssamSchema, SSAM_SCHEMA_FILE);
    }
    catch (LDAPException ldape)
    {
      throw new InstallerException("Failed to establish a connection to" +
              " the server " + localHostName + ":" + ldapPort + ". Make sure" +
              " the server is available and that " + ldapPort + " is" +
              ((useStartTLSArg.isPresent() || useSSLArg.isPresent()) ?
                      " a secure" : " an unsecure") + " port, as the" +
              " options you have specified indicate.", ldape,
              ResultCode.UNAVAILABLE);
    }

    try
    {
      ssamUserDN = ssamUserDNArg.isPresent() ? ssamUserDNArg.getValue() :
        new DN(new RDN("cn", "SSAM User"), new DN(baseDN));
    }
    catch (LDAPException le)
    {
      throw new InstallerException("Error creating SSAM User DN");
    }

    // Read the server's Java configuration file and make sure the server
    // has a PermGen specified, since otherwise the server will likely not
    // be able to host the application without out-of-memory errors.
    if (deploySSAM())
    {
      int javaMajorVersion = 0;
      try
      {
        SearchResultEntry systemPropertyValues = ldapConnection.getEntry(
          "cn=System Information,cn=monitor", "SystemProperty");
        if (systemPropertyValues != null)
        {
          for (final String systemProperty :
                     systemPropertyValues.getAttributeValues("systemProperty"))
          {
            if (systemProperty.startsWith("java.version"))
            {
              final Pattern javaMajorVersionPattern = Pattern.compile("^java\\.version=\\s*'1\\.(\\d+).*'.*$");
              final Matcher matcher = javaMajorVersionPattern.matcher(systemProperty);
              if (matcher.matches())
              {
                javaMajorVersion = Integer.valueOf(matcher.group(1));
              }
            }
          }
        }
        if (javaMajorVersion == 0)
        {
          System.err.println("Could not determine Java major version from server system properties!");
        }
      }
      catch (final LDAPException le)
      {
        throw new InstallerException(
          "Could not determine version of Java the server is running, error while" +
          " searching for 'java.version' system property: " + le.getDiagnosticMessage());
      }

      Properties javaProperties = new Properties();
      File javaPropertiesFile = new File(serverRoot, "config/java.properties");
      try (FileInputStream fis = new FileInputStream(javaPropertiesFile))
      {
        javaProperties.load(fis);
        String startProfile;
        String startProfileName = "start-server.java-args";
        startProfile = javaProperties.getProperty(startProfileName);
        if (startProfile == null)
        {
          // Check legacy names
          if (isDirectoryServer)
          {
            startProfileName = "start-ds.java-args";
          } else
          {
            startProfileName = "start-proxy.java-args";
          }
          startProfile = javaProperties.getProperty(startProfileName);
        }
        if (startProfile != null)
        {
          // Java 8 and later does not need or use a PermGen setting.
          if ((javaMajorVersion > 0) &&  (javaMajorVersion < 8))
          {
            Pattern p = Pattern.compile(".*\\s-XX:PermSize=(\\d+)([bBkKmMgG]).*");
            Matcher m = p.matcher(startProfile);
            if (! m.matches())
            {
              // Before 5.2, servers may not have a PermGen setting.
              // Servers installed with version 5.2 and later on Java 7 should
              // have the default PermGen size of 256M assuming the heap size
              // is greater than 1G.
              throw new InstallerException(
                "The server's Java configuration does not specify an option" +
                " for the initial permanent generation memory size (-XX:PermSize) which" +
                " will cause the server to experience out-of-memory exceptions" +
                " while hosting SSAM.  You should stop the server and edit" +
                " config/java.properties, adding -XX:PermSize=256M to the " + startProfileName +
                " profile.  Then run dsjavaproperties before restarting" +
                " the server.");
            }
            else
            {
              // Ensure that the PermSize is at least 256M.
              try
              {
                String ordinal = m.group(1);
                String unit    = m.group(2);
                Long permSizeBytes = Long.parseLong(ordinal);
                if (unit.equalsIgnoreCase("k"))
                {
                  permSizeBytes = permSizeBytes * 1024L;
                }
                else if (unit.equalsIgnoreCase("m"))
                {
                  permSizeBytes = permSizeBytes * 1024L * 1024L;
                }
                else if (unit.equalsIgnoreCase("g"))
                {
                  permSizeBytes = permSizeBytes * 1024L * 1024L * 1024L;
                }
                if (permSizeBytes < /** 256M */ 256L * 1024L * 1024L)
                {
                  throw new InstallerException(
                    "The server's Java configuration specifies --XX:PermSize=" +
                    ordinal + unit + " which may be inadequate for hosting SSAM," +
                    " potentially causing the server to experience out-of-memory" +
                    " exceptions.  You should stop the server and edit config/java.properties," +
                    " specifying -XX:PermSize=256M or more for the " + startProfileName +
                    " profile.  Then run dsjavaproperties before restarting" +
                    " the server.");
                }
              }
              catch (NumberFormatException nfe)
              {
                LOG(nfe);
              }
            }
          }
        }
        else
        {
          throw new InstallerException(
                  "Failed to find the server start command " + startProfileName +
                          " in Java config file " + javaPropertiesFile.getPath() + ".");
        }
      }
      catch (IOException ioe)
      {
        throw new InstallerException(
                "Error reading Java configuration file " + javaPropertiesFile.getPath(),
                ioe);
      }
    }


    // Directory under the server root where the SSAM war will be place and SSAM
    // can pick up important config files.
    webAppsDir = new File(serverRoot, "webapps");
    ssamConfigDir = new File(webAppsDir, "ssam-config");

    // The password is written to the resource directory so it can
    // be respecified when SSAM is deployed on the Proxy.
    ssamUserPasswordResourceFile = new File(resourceDir, SSAM_PIN);
    passwordFromResourcePINFile = false;

    // If a password file exists in the resource directory, use it since the
    // password must be the same on all backend servers that are prepared by
    // this tool.  Otherwise, either read the SSAM user password from the
    // supplied file and compare them, or generate a new one.
    if (ssamUserPasswordResourceFile.exists())
    {
      final String resourceFilePassword = new String(Files.readAllBytes(
        ssamUserPasswordResourceFile.toPath())).trim();

      if (ssamUserPasswordFileArg.isPresent())
      {
        if (! getUserPasswordFromFileArg().equals(resourceFilePassword))
        throw new InstallerException("A password for the SSAM user account has" +
                " already been generated and stored in " +
                ssamUserPasswordResourceFile.getCanonicalPath() + ", but it does " +
                "not match the password provided in the --" +
          ssamUserPasswordFileArg.getLongIdentifier() + " argument. Check the " +
                "SSAM user password, omit password arguments to use the " +
                "generated password, or delete the resource/ssam.pin file.");
      }
      if (ssamUserPasswordArg.isPresent())
      {
        throw new InstallerException("A password for the SSAM user account has" +
                " already been generated and stored in " +
                ssamUserPasswordResourceFile.getCanonicalPath() + ", but it does " +
                "not match the password provided in the --" +
          ssamUserPasswordArg.getLongIdentifier() + " argument. Check the " +
                "SSAM user password or omit password arguments to use the " +
                "generated password, or delete the resource/ssam.pin file.");
      }

      ssamUserPassword = resourceFilePassword;
      passwordFromResourcePINFile = true;
    }
    else if (! isDirectoryServer)
    {
      // If this is a Proxy Server, the presumption is that the Directory Server
      // has already been configured for SSAM access and the password
      // already generated.
      throw new InstallerException(
              "To deploy SSAM on a Directory Proxy Server, you must setup the" +
                      " Directory Proxy Server's backend servers, and then run this tool" +
                      " on the Proxy Server.");
    }
    else if (ssamUserPasswordFileArg.isPresent())
    {
      ssamUserPassword = getUserPasswordFromFileArg();
    }
    else if (ssamUserPasswordArg.isPresent())
    {
      ssamUserPassword = ssamUserPasswordArg.getValue();
    }
    else
    {
      final SecureRandom random = new SecureRandom();
      ssamUserPassword = new BigInteger(130, random).toString(32);
    }


    // Write the SSAM User password file to the config directory.
    // The password is written to the resource directory so it can
    // be re-used when SSAM is deployed on the Proxy Server.
    if (! ssamUserPasswordResourceFile.exists())
    try
    {
      writeToFile(ssamUserPasswordResourceFile, ssamUserPassword);
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Error writing " + ssamUserPasswordConfigFile,
              ioe);
    }

    // The file that will be written when deploying the web app.
    ssamUserPasswordConfigFile = new File(ssamConfigDir, SSAM_PIN);

    System.out.println("Done");
  }


  /**
   * Gets the SSAM user password from a file argument.
   *
   * @return the SSAM user password stored in a file
   */
  private String getUserPasswordFromFileArg()
  {
    try
    {
      List<String> pwFileContents = ssamUserPasswordFileArg.getFileLines();
      if (pwFileContents == null || pwFileContents.isEmpty())
      {
        throw new InstallerException(
          "File " + ssamUserPasswordFileArg.getValue().getCanonicalPath() +
            " specified by --" + ssamUserPasswordFileArg.getLongIdentifier() +
            " is empty.");
      }
      return pwFileContents.get(0).trim();
    }
    catch (IOException ioe)
    {
      throw new InstallerException(
        "Failed to read the SSAM User password from " + ssamUserPasswordFileArg.getValue(),
        ioe);
    }
  }


  /**
   * Copies files to the server root and/or resource directory.
   */
  private void deployFiles()
  {
    if (deploySSAM())
    {
      // Create the webapps and webapps/ssam-config directories.
      if (!ssamConfigDir.exists() && !ssamConfigDir.mkdirs())
      {
        throw new InstallerException(
                "Failed to create " + ssamConfigDir.getPath());
      }

      System.out.print("Deploying Files ..... ");
      if (ssamUserPasswordConfigFile.exists() && !ssamUserPasswordConfigFile.delete())
      {
        throw new InstallerException(
                "Failed to delete existing " + ssamUserPasswordConfigFile.getPath());
      }
      try
      {
        writeToFile(ssamUserPasswordConfigFile, ssamUserPassword);
      }
      catch (IOException ioe)
      {
        throw new InstallerException("Error writing " + ssamUserPasswordConfigFile,
                ioe);
      }

      // Write the LDAP connection details file to the config directory.
      File ldapConnectionDetailsFile = new File(ssamConfigDir,
              "ldap-connection-details.json");
      if (ldapConnectionDetailsFile.exists() && !ldapConnectionDetailsFile.delete())
      {
        throw new InstallerException(
                "Failed to delete existing " + ldapConnectionDetailsFile.getPath());
      }
      try
      {
        writeLDAPConnectionDetails(ldapConnectionDetailsFile);
      }
      catch (IOException ioe)
      {
        throw new InstallerException(
                "Error writing " + ldapConnectionDetailsFile, ioe);
      }


      // Write the application.properties file to the config directory.
      final File applicationProperties = new File(ssamConfigDir,
              "application.properties");
      if (applicationProperties.exists() && !applicationProperties.delete())
      {
        throw new InstallerException(
                "Failed to delete existing " + applicationProperties.getPath());
      }
      try
      {
        // Set up a map of replacement tokens.  Keys may contain an equals sign (=), in which case the entire line
        // is replaced with the value.  Otherwise, the key is assumed to be a property name whose value will be
        // assigned the map value.
        Map<String, String> replaceTokens = new HashMap<>();

        // Both arguments must be present, or neither.
        if (reCaptchaSiteKeyArg.isPresent())
        {
          replaceTokens.put("recaptchaSiteKey", reCaptchaSiteKeyArg.getValue());
          replaceTokens.put("recaptchaSecretKey",
                  reCaptchaSecretKeyArg.getValue());
        }

        // Both arguments must be present, or neither.
        if (pingAccessLogoutURLArg.isPresent())
        {
          // Only one profile should be active at one time.
          replaceTokens.put("spring.profiles.active=ldap-authentication",
                  "#spring.profiles.active=ldap-authentication");
          replaceTokens.put("#spring.profiles.active=ping-authentication",
                  "spring.profiles.active=ping-authentication");

          replaceTokens.put("pingFederateLogoutURL",
                  pingFederateLogoutURLArg.getValue());
          replaceTokens.put("pingAccessLogoutURL",
                  pingAccessLogoutURLArg.getValue());
        }

        replaceTokens.put("ldapConnectionDetailsResource",
                "file:" + ldapConnectionDetailsFile.getCanonicalPath());
        replaceTokens.put("baseDN", peopleBaseDNArg.getStringValue());

        // Write application.properties in the SSAM config directory, replacing
        // tokens with their values.
        writeApplicationConfiguration(applicationProperties, replaceTokens);
      }
      catch (IOException ioe)
      {
        throw new InstallerException(
                "Error writing " + ldapConnectionDetailsFile, ioe);
      }


      // Copy the WAR file to the server's webapps directory.
      final Path warFileSourcePath = new File(sourceDir,
              WAR_FILE_NAME).toPath();
      final Path warFileTargetPath = new File(webAppsDir,
              WAR_FILE_NAME).toPath();
      try
      {
        Files.copy(warFileSourcePath, warFileTargetPath,
                StandardCopyOption.REPLACE_EXISTING);
      }
      catch (IOException ioe)
      {
        throw new InstallerException(
                "Failed to copy " + warFileSourcePath + " to " + webAppsDir,
                ioe);
      }

      System.out.println("Done");
    }
  }



  /**
   * Provisions the SSAM user and ACIs to the Directory Server.
   */
  private void provisionSSAMUser()
  {
    if (isDirectoryServer)
    {
      System.out.print("Provisioning SSAM User ..... ");

      Set<Attribute> ssamUserAttrs = new HashSet<>();
      ssamUserAttrs.add(new Attribute("objectClass", "top", "person",
              "organizationalPerson", "inetOrgPerson"));
      ssamUserAttrs.add(new Attribute("givenName", "SSAM"));
      final RDN[] userRDNs = ssamUserDN.getRDNs();
      String cn = "";
      String sn = "";
      for (final RDN rdn : userRDNs)
      {
        for (final String attr : rdn.getAttributeNames())
        {
          if (attr.equalsIgnoreCase("cn") && rdn.getAttributeValues().length > 0)
          {
            cn = rdn.getAttributeValues()[0];
          }
        }
      }
      if (cn.isEmpty())
      {
        cn = "SSAM User";
      }
      else
      {
        sn = (cn.lastIndexOf(' ') == -1) ? "User" :
          cn.substring(Math.min(cn.lastIndexOf(' ') + 1, cn.length()));
      }
      if (sn.isEmpty())
      {
        sn = "User";
      }
      boolean ssamUserExists;
      try
      {
        ssamUserExists = (null != ldapConnection.getEntry(ssamUserDN.toString()));
      }
      catch (LDAPException le)
      {
        throw new InstallerException("Failed to search for existing SSAM user " + ssamUserDN, le);
      }
      if (ssamUserExists)
      {
        // Validate password or reset ssam user password
        if (resetSSAMUserPasswordArg.isPresent())
        {
          LOG("Resetting existing SSAM user entry " + ssamUserDN.toString() + " password.");
          try
          {
            // If ACI or privileges change later, these will have to be documented and manually-added
            ExtendedResult result = ldapConnection.processExtendedOperation(
              new PasswordModifyExtendedRequest(ssamUserDN.toString(), null, ssamUserPassword));
            if (result.getResultCode().intValue() != ResultCode.SUCCESS_INT_VALUE)
            {
              throw new InstallerException(
                "Failed to reset the password for existing SSAM user " + ssamUserDN +
                  ", LDAP result code " + result.getResultCode().intValue() + ":  " +
                   result.getDiagnosticMessage());
            }
          }
          catch (LDAPException le)
          {
            throw new InstallerException(
              "Failed to reset the password for existing SSAM user " + ssamUserDN, le);
          }
          LOG("SSAM user password reset.");
        }
        else
        {
          if (! passwordFromResourcePINFile &&
              ! (ssamUserPasswordArg.isPresent() || ssamUserPasswordFileArg.isPresent()) )
          {
            throw new InstallerException("SSAM user account exists and neither " +
              "the password nor pin file was provided.");
          }
          LOG("Validating the password for SSAM user entry " + ssamUserDN.toString());
          LDAPConnection ssamUserBindConnection = null;
          try
          {
            ssamUserBindConnection = setUpSecureConnection(ldapPortArg.getValue());
            BindResult result = ssamUserBindConnection.bind(ssamUserDN.toString(), ssamUserPassword);
            if (result.getResultCode().intValue() != ResultCode.SUCCESS_INT_VALUE)
            {
              throw new InstallerException(
                "Failed to validate the password for existing SSAM user " + ssamUserDN +
                  ", LDAP result code " + result.getResultCode().intValue() + ":  " +
                    result.getDiagnosticMessage());
            }
          }
          catch (IOException ie)
          {
            throw new InstallerException(
              "Failed to validate the password for existing SSAM user " + ssamUserDN, ie);
          }
          catch (LDAPException le)
          {
            throw new InstallerException(
              "Failed to validate the password for existing SSAM user " + ssamUserDN, le);
          }
          finally
          {
            if (null != ssamUserBindConnection)
            {
              ssamUserBindConnection.close();
            }
          }
          LOG("SSAM user account password validated.");
        }
      }
      else
      {
        ssamUserAttrs.add(new Attribute("sn", sn));
        ssamUserAttrs.add(new Attribute("cn", cn));
        ssamUserAttrs.add(new Attribute("ds-privilege-name", "proxied-auth", "password-reset"));
        ssamUserAttrs.add(new Attribute("userPassword", ssamUserPassword));
        Entry ssamUserEntry = new Entry(ssamUserDN, ssamUserAttrs);

        try
        {
          LOG("Adding SSAM user entry " + ssamUserDN.toString() + ": " + "" + ssamUserEntry.toString());
          ldapConnection.add(ssamUserEntry);
          LOG("SSAM user added");
        }
        catch (LDAPException le)
        {
          throw new InstallerException("Failed to add SSAM user " + ssamUserDN.toString(), le);
        }
      }

      // Add ACIs to the base entry.
      Modification aciMod = new Modification(ModificationType.ADD, "aci",
              "(targetattr=\"*\")(version 3.0; acl \"Grant SSAM access to modify entry attributes\"; allow (all,proxy) userdn=\"ldap:///" + ssamUserDN + "\";)",
              "(targetattr=\"ds-pwp-account-disabled\")(version 3.0; acl \"Grant SSAM access to modify the ds-pwp-account-disabled operational attribute\"; allow (all,proxy) userdn=\"ldap:///" + ssamUserDN + "\";)",
              "(extop=\"1.3.6.1.4.1.30221.2.6.43\")(version 3.0; acl \"Grant SSAM access to Get Password Quality Requirements Request\"; allow (read) userdn=\"ldap:///" + ssamUserDN + "\";)",
              "(extop=\"1.3.6.1.4.1.30221.2.6.45\")(version 3.0; acl \"Grant SSAM access to Deliver Password Reset Token Request\"; allow (read) userdn=\"ldap:///" + ssamUserDN + "\";)",
              "(extop=\"1.3.6.1.4.1.30221.2.6.49\")(version 3.0; acl \"Grant SSAM access to Deliver Single Use Token Request\"; allow (read) userdn=\"ldap:///" + ssamUserDN + "\";)",
              "(extop=\"1.3.6.1.4.1.30221.2.6.51\")(version 3.0; acl \"Grant SSAM access to Consume Single Use Token Request\"; allow (read) userdn=\"ldap:///" + ssamUserDN + "\";)");
      try
      {
        // User permissive modify in case one of the ACIs already exists.
        // Ideally we would clean up ACIs from previous failed install attempts
        // but doing so is complicated and more trouble than it is worth.
        ModifyRequest req = new ModifyRequest(baseDN, aciMod,
                PERMISSIVE_MODIFY_CONTROL);
        ldapConnection.modify(req);
        LOG("ACIs added: " + aciMod.toString());
      }
      catch (LDAPException le)
      {
        throw new InstallerException(
                "Failed to add ACIs to base entry " + baseDN, le);
      }
      System.out.println("Done");
    }
  }



  /**
   * Runs dsconfig.
   */
  private void configureServer()
  {
    final List<String> dsCfgCommands = new ArrayList<>();
    final List<String> deploySsamCfgCommands = new ArrayList<>();

    dsCfgCommands.add("dsconfig create-external-server" +
            " --server-name SMTP" +
            " --type smtp" +
            " --set server-host-name:" + smtpServerHostnameArg.getValue() +
            (!smtpServerUsernameArg.isPresent() ? "" :
                    " --set user-name:" + smtpServerUsernameArg.getValue() +
                    " --set password:" + smtpServerPasswordArg.getValue()));

    // In case the external server object above already exists.
    dsCfgCommands.add("dsconfig set-external-server-prop" +
            " --server-name SMTP" +
            " --set server-host-name:" + smtpServerHostnameArg.getValue() +
            (!smtpServerUsernameArg.isPresent() ? "" :
                    " --set user-name:" + smtpServerUsernameArg.getValue() +
                    " --set password:" + smtpServerPasswordArg.getValue()));


    dsCfgCommands.add(
            "dsconfig set-global-configuration-prop" + " --add smtp-server:SMTP");

    dsCfgCommands.add("dsconfig create-otp-delivery-mechanism" +
            " --mechanism-name Email" +
            " --type email" +
            " --set enabled:true" +
            " --set 'sender-address:" + smtpSenderEmailAddressArg.getValue() + "'");

    // In case the server already exists.
    dsCfgCommands.add("dsconfig set-otp-delivery-mechanism-prop" +
            " --mechanism-name Email" +
            " --set 'sender-address:" + smtpSenderEmailAddressArg.getValue() + "'");

    dsCfgCommands.add("dsconfig set-password-generator-prop" +
            " --generator-name \"One-Time Password Generator\"" +
            " --set password-format:numeric:6");

    dsCfgCommands.add("dsconfig create-extended-operation-handler" +
            " --handler-name \"Password Reset Token\"" +
            " --type deliver-password-reset-token" +
            " --set enabled:true" +
            " --set \"password-generator:One-Time Password Generator\"" +
            " --set default-token-delivery-mechanism:Email");

    dsCfgCommands.add("dsconfig create-sasl-mechanism-handler" +
            " --handler-name UNBOUNDID-DELIVERED-OTP" +
            " --type unboundid-delivered-otp" +
            " --set enabled:true" +
            " --set \"identity-mapper:Exact Match\"");

    dsCfgCommands.add("dsconfig create-extended-operation-handler" +
            " --handler-name Single-Use-Token" +
            " --type single-use-tokens" +
            " --set enabled:true" +
            " --set \"password-generator:One-Time Password Generator\"" +
            " --set default-otp-delivery-mechanism:Email");

    dsCfgCommands.add("dsconfig set-plugin-prop" +
            " --plugin-name \"UID Unique Attribute\"" +
            " --set enabled:true");

    dsCfgCommands.add("dsconfig create-plugin" +
            " --plugin-name \"Mail Unique Attribute\"" +
            " --type unique-attribute" +
            " --set enabled:true --set type:mail");

    dsCfgCommands.add("dsconfig set-identity-mapper-prop" +
            " --mapper-name \"Exact Match\"" +
            " --add match-attribute:mail");

    dsCfgCommands.add("dsconfig create-local-db-index" +
            " --backend-name userRoot" +
            " --index-name mobile" +
            " --set index-type:equality");

    deploySsamCfgCommands.add("dsconfig create-web-application-extension" +
            " --extension-name \"SSAM\"" +
            " --set base-context-path:/ssam" +
            " --set war-file:webapps/" + WAR_FILE_NAME);

    deploySsamCfgCommands.add("dsconfig set-connection-handler-prop" +
            " --handler-name \"HTTPS Connection Handler\"" +
            " --add \"web-application-extension:SSAM\"");

    deploySsamCfgCommands.add("dsconfig set-log-publisher-prop" +
            " --publisher-name \"HTTP Detailed Access\"" +
            " --set suppressed-request-parameter-name:currentPassword" +
            " --set suppressed-request-parameter-name:userPassword" +
            " --set suppressed-request-parameter-name:j_password" +
            " --set suppressed-request-parameter-name:password");

    // Disable and re-enable the connection handler so the changes take effect.
    deploySsamCfgCommands.add("dsconfig set-connection-handler-prop" +
            " --handler-name \"HTTPS Connection Handler\"" +
            " --set enabled:false");
    deploySsamCfgCommands.add("dsconfig set-connection-handler-prop" +
            " --handler-name \"HTTPS Connection Handler\"" +
            " --set enabled:true");

    File dsDsConfig = new File(resourceDir, SSAM_DS_DSCONFIG);
    File ssamDeployDsConfig = new File(resourceDir, SSAM_DEPLOY_DSCONFIG);
    try
    {
      writeToFile(dsDsConfig, dsCfgCommands);

      if (deploySSAM())
      {
        writeToFile(ssamDeployDsConfig, deploySsamCfgCommands);
      }
    }
    catch (IOException ioe)
    {
      throw new InstallerException("Failed to write file", ioe);
    }

    try
    {
      // Update the schema if necessary.
      if (! schemaMods.isEmpty())
      {
        // The schema will only be updated if it does not exist on the server,
        // since doing to will fail because it is read-only.  Assume that the
        // server's version is the right one but a warning is logged for
        // reference.  This should really only be necessary for 5.1 servers.
        // Also the server-root argument is not required when configuring
        // backend servers, but the current version of SSAM does not officially
        // support Proxy installation.
        if (serverRootArg.isPresent())
        {
          if (! new File(serverRootArg.getValue(), "/config/schema/" + SSAM_SCHEMA_FILE).exists())
          {
            System.out.print("Updating Schema ..... ");
            ldapConnection.modify("cn=schema", schemaMods);
            System.out.println("Done");
          }
          else
          {
            String modString = "";
            for (Modification mod : schemaMods)
            {
              modString += mod.toString() + "\n";
            }
            LOG("\nWARNING:  The schema file " + SSAM_SCHEMA_FILE + " packaged with SSAM differs" +
                    " from the one packaged with the server:\n\n +" + modString);
          }
        }
        else
        {
          LOG("\nWARNING:  The --" + serverRootArg.getLongIdentifier() + " was not supplied and the" +
                  " installer could not determine whether the configured server required" +
                  " schema modification.  If so, you should copy " + SSAM_SCHEMA_FILE +
                  " to the server's config/schema directory after deployment, and restart the server.");
        }
      }

      // Directory specific configuration.
      System.out.print("Configuring Server ..... ");

      List<String> connectionArgs = new ArrayList<>();
      connectionArgs.add("--port");
      connectionArgs.add(String.valueOf(ldapPortArg.getValue()));
      connectionArgs.add("--bindDN");
      connectionArgs.add(String.valueOf(bindDNArg.getValue()));
      connectionArgs.add("--bindPassword");
      connectionArgs.add(bindPasswordArg.getValue());

      if (useSSLArg.isPresent())
      {
        connectionArgs.add("--useSSL");
      }
      else if (useStartTLSArg.isPresent())
      {
        connectionArgs.add("--useStartTLS");
      }
      else
      {
        connectionArgs.add("--useNoSecurity");
      }

      if (trustStorePathArg.isPresent())
      {
        connectionArgs.add("--trustStorePath");
        connectionArgs.add(trustStorePathArg.getValue().getCanonicalPath());
      }
      else if (trustAllArg.isPresent())
      {
        connectionArgs.add("--trustAll");
      }

      List<String> dsconfigArgs = new ArrayList<>();
      final String dsConfigPath =
        StaticUtils.isWindows() ? serverRootArg.getValue() + "\\bat\\dsconfig.bat" : "bin/dsconfig";
      dsconfigArgs.add(dsConfigPath);
      dsconfigArgs.add("--no-prompt");
      dsconfigArgs.add("--batch-continue-on-error");

      dsconfigArgs.add("--applyChangeTo");
      dsconfigArgs.add("single-server");

      dsconfigArgs.addAll(connectionArgs);

      List<String> args;

      if (isDirectoryServer)
      {
        args = new ArrayList<>(dsconfigArgs);
        args.add("--batch-file");
        args.add(dsDsConfig.getCanonicalPath());

        // Configure the server.
        runCommand(null, args);
      }
      if (deploySSAM())
      {
        args = new ArrayList<>(dsconfigArgs);
        args.add("--batch-file");
        args.add(ssamDeployDsConfig.getCanonicalPath());

        // Create Web App Extensions etc.
        runCommand(null, args);
      }
      System.out.println("Done");

      boolean outputRebuildIndexMessage = true;
      try
      {
        if (isDirectoryServer)
        {
          boolean rebuildIndexes = false;
          long entryCount = 0;
          final SearchResult entryCountResults = ldapConnection.search(
            "cn=monitor", SearchScope.SUB,
            "(&(objectclass=ds-backend-monitor-entry)(ds-backend-base-dn=" + baseDN + "))",
            "ds-backend-entry-count");
          if ( (entryCountResults.getResultCode() == ResultCode.SUCCESS) &&
               (entryCountResults.getEntryCount() > 0) )
          {
            final SearchResultEntry entry = entryCountResults.getSearchEntries().get(0);
            final String entryCountStr = entry.getAttributeValue("ds-backend-entry-count");
            if (entryCountStr != null && !entryCountStr.isEmpty())
            {
              entryCount = Long.valueOf(entryCountStr);
              if (entryCount <= 100000L)
              {
                rebuildIndexes = true;
              }
            }
          }

          if (rebuildIndexes && entryCount > 0)
          {
            args = new ArrayList<>();
            if (StaticUtils.isWindows())
            {
              args.add(serverRootArg.getValue() + "\\bat\\rebuild-index.bat");
            }
            else
            {
              args.add("bin/rebuild-index");
            }
            args.add("--task");
            args.add("--baseDN");
            args.add(baseDN);
            args.add("--index");
            args.add("mobile");
            args.addAll(connectionArgs);

            // Rebuild indexes.
            runCommand("Rebuilding required indexes for " + entryCount + " entries ..... ", args);

            System.out.println("Done");
            outputRebuildIndexMessage = false;
          }
        }
      }
      finally
      {
        final String rebuildIndexMessage =
          "The installer adds required indexes to improve searches used by this application." +
            " The following command is used to rebuild the indexes used by" +
            " the application. Run this command at the Directory Server:\n\n" +
            "     rebuild-index --task --baseDN \"" + baseDN + "\" --index mobile";
        if (outputRebuildIndexMessage)
        {
          System.out.println();
          System.out.println("WARNING: The required attribute indexes have not been" +
            " automatically rebuilt by this installer. Without the required indexes," +
            " key searches will be unindexed and fail. It is highly recommended that" +
            " you schedule time to run the following command manually.");
          System.out.println();

          System.out.println(rebuildIndexMessage);
        }
        LOG(rebuildIndexMessage);
        System.out.println();
        System.out.println("The rebuild-index command has been written to the installer" +
          " log file for future reference.");
      }
    }
    catch (Exception e)
    {
      throw new InstallerException(
              "Installation failed:" + e.getLocalizedMessage(), e);
    }
  }



  /**
   * Display final messages.
   */
  private void finish()
  {
    System.out.println();
    System.out.println("See " + resourceDir.getPath() + " for logs and content" +
            " generated by this tool.");

    if (! noDeployArg.isPresent())
    {
      String url = "https://" + localHostName + ":" + httpsPort + "/ssam";
      System.out.println();
      if (pingAccessLogoutURLArg.isPresent())
      {
        System.out.println(
                "PingAccess can be configured to access SSAM at:\n\n\t" + url
                        + "\n");
      }
      else
      {
        System.out.println("SSAM can be accessed at:\n\n\t" + url + "\n");
      }

    }
  }



  /**
   * Writes the LDAP connection details JSON file that governs how SSAM
   * is configured to communicate with the server.
   */
  private void writeLDAPConnectionDetails(final File details) throws IOException
  {

    // Generate the server-details section.
    JSONObject serverDetails = new JSONObject(new JSONField("single-server",
            new JSONObject(new JSONField("address", localHostName),
                    new JSONField("port", ldapPortArg.getValue()))));

    // Generate the communication-security section.
    List<JSONField> fields = new ArrayList<>();
    if (useSSLArg.isPresent() || useStartTLSArg.isPresent())
    {
      if (useSSLArg.isPresent())
      {
        fields.add(new JSONField("security-type", "SSL"));
      }
      else
      {
        fields.add(new JSONField("security-type", "StartTLS"));
      }
      if (trustStorePathArg.isPresent())
      {
        fields.add(new JSONField("trust-store-file", trustStorePathArg.getValue().getCanonicalPath()));
        fields.add(new JSONField("trust-store-type", "JKS"));
        fields.add(new JSONField("verify-address-in-certificate", true));
      }
      else
      {
        fields.add(new JSONField("trust-all-certificates", true));
      }
    }
    else
    {
      fields.add(new JSONField("security-type", "none"));
    }
    JSONObject communicationSecurity = new JSONObject(
            fields.toArray(new JSONField[fields.size()]));

    // Generate the authentication-details section.
    JSONObject authenticationDetails = new JSONObject(
            new JSONField("authentication-type", "simple"),
            new JSONField("dn", ssamUserDN.toString()),
            new JSONField("password-file",
            ssamUserPasswordConfigFile.getCanonicalPath()));

    // ldap-connection-details.json
    JSONObject ldapConnectionDetails = new JSONObject(
            new JSONField("server-details", serverDetails),
            new JSONField("communication-security", communicationSecurity),
            new JSONField("authentication-details", authenticationDetails));

    writeToFile(details, ldapConnectionDetails.toString());
  }



  /**
   * Reads the stock application.properties file from the class loader, substituting
   * input values for configuration properties, and then writing the file to the
   * server's config directory, where it will override the stock file.
   */
  private void writeApplicationConfiguration(final File file,
                                             final Map<String, String> propertiesAndValues)
          throws IOException
  {
    try (BufferedReader in = new BufferedReader(new InputStreamReader(
            this.getClass().getClassLoader().getResourceAsStream(
                    "application.properties")));
         BufferedWriter out = new BufferedWriter(new FileWriter(file)))
    {
      String line;
      while (null != (line = in.readLine()))
      {
        for (String token : propertiesAndValues.keySet())
        {
          if (line.startsWith(token))
          {
            if (!token.contains("="))
            {
              line = token + "=" + propertiesAndValues.get(token).replace("\\", "\\\\");
            }
            else
            {
              line = propertiesAndValues.get(token).replace("\\", "\\\\");
            }
          }
        }
        out.write(line);
        out.newLine();
      }
    }
  }



  /**
   * Runs a filesystem command, directing output to this tool's log file.
   *
   * @param status to print to the terminal.
   * @param args   is the command and all its arguments
   * @return command output as a String
   */
  private String runCommand(String status, List<String> args)
  {
    String commandAndArgs = Arrays.toString(args.toArray());
    LOG("=== Running command: " + commandAndArgs);
    Process p;
    final ProcessBuilder pb = new ProcessBuilder(args);
    pb.directory(serverRootArg.getValue());
    pb.redirectErrorStream(true);
    StringBuilder output = new StringBuilder();
    try
    {
      if (status != null)
      {
        System.out.print(status);
      }
      p = pb.start();
      CommandOutputHandler outputHandler = new CommandOutputHandler(
              p.getInputStream(), output);
      outputHandler.start();
      p.waitFor();
      outputHandler.readFullyAndClose();
      if (p.exitValue() != 0)
      {
        LOG("Command " + commandAndArgs + " failed with exit code " +
                p.exitValue() + ". Command output: ");
        LOG(output.toString());
        throw new InstallerException("Command " + args.get(
                0) + " failed.  See " + logFile.getCanonicalPath());
      }
    }
    catch (Exception e)
    {
      LOG(e);
      if (e instanceof InstallerException)
      {
        throw (InstallerException)e;
      }
      else
      {
        throw new InstallerException(
                "Failed to run " + Collections.singletonList(args), e);
      }
    }
    finally
    {
      LOG("=== Finished command: " + commandAndArgs);
    }
    return output.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override
  public String getToolName()
  {
    if (StaticUtils.isWindows())
    {
      return "setup.bat";
    }
    else
    {
      return "setup.sh";
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override
  public String getToolDescription()
  {
    // The LDAP SDK will remove formatting such as newlines when displaying this text.
    return "Installs the Self Service Account Manager (SSAM) application.  " +

            "SSAM may be hosted on a Ping Directory Server or other servlet " +
            "container. Before installing SSAM, setup the server to host SSAM, " +
            "specifying an HTTPS port.  Make sure that the server's Java " +
            "configuration specifies at least 128M for its -XX:PermSize JVM option in " +
            "its config/java.properties file.  If not, add -XX:PermSize=128M to the " +
            "start-server.java-args property and run dsjavaproperties. " +
            "Have the connection details ready for interacting with the server (host, port, " +
            "bind DN password), the base DN where user entries are located, and the host " +
            "name of an SMTP mail server that will be used for notifications.\n" +

            "This tool may be used both for configuring a Directory Server for access by SSAM, " +
            "as well as configuring or Directory Server for hosting the " +
            "SSAM web application.  If installing SSAM on a Directory Server, run " +
            "this tool once.  When installing SSAM in an external servlet container, first run this tool " +
            "against the Directory Servers with the --noDeploy option, then configure SSAM with using " +
            "the generated output in the resource directory of the exploded " +
            "ZIP archive.\n" +

            "When configuring a Directory Server for access, this tool will:\n" +

            "  - Create a SSAM user entry with ACIs that SSAM will use when binding to\n" +
            "    the Directory Server.\n" +
            "  - Update the schema if necessary.\n" +
            "  - Configure the server for communicating with the SMTP server, and configure\n" +
            "    an email one-time password mechanism (for the full set of configured\n" +
            "    changes, see resource/" + SSAM_DS_DSCONFIG + " after running this tool).\n" +
            "  - Rebuild the indexes.\n" +

            "When configuring a Directory Server for hosting SSAM, this tool will:\n" +

            "  - Ensure that the server has sufficient resources for hosting the\n" +
            "    application.\n" +
            "  - Configure the server for hosting SSAM by creating a Web Application\n" +
            "    Extension and adding it to the server's HTTPS Connection Handler\n" +
            "    (for the full set of configured changes, see\n" +
            "    resource/" + SSAM_DEPLOY_DSCONFIG + " after running this tool).\n" +
            "  - Configure SSAM for accessing the Directory Server by generating configuration\n" +
            "    and password.\n" +

            "After installation, the Directory Server can be configured with additional single use token " +
            "delivery mechanisms other than email (e.g. Twilio for SMS).  In order to configure " +
            "these, use dsconfig to create the single use token delivery mechanisms, and " +
            "then edit the \"Password Reset Token\" and \"Single-Use-Token\" extended operation " +
            "handlers to reference them.  When sending single use tokens or password reset tokens, " +
            "the server will first look at the \"ds-auth-preferred-otp-delivery-mechanism\" " +
            "attribute in the user entry to see if the user has a preference.  If not, it will " +
            "iterate through the delivery mechanisms for the extended operation handler in the " +
            "order that they are defined, using the first one that is able to successfully deliver " +
            "the notification.";
  }



  /**
   * {@inheritDoc}
   */
  @Override
  public LinkedHashMap<String[], String> getExampleUsages()
  {
    LinkedHashMap<String[], String> exampleUsages = new LinkedHashMap<>();

    exampleUsages.put(new String[]{
            "--serverRoot", "/path/to/ds/install/dir",
            "--ldapPort", "636",
            "--bindDN", "cn=Directory Manager",
            "--bindPassword", "password",
            "--useSSL",
            "--trustStorePath", "/path/to/ds/install/dir/config/keystore",
            "--peopleBaseDN", "ou=People,dc=example,dc=com",
            "--smtpServerHostname", "smtp.example.com",
            "--smtpSenderEmailAddress", "do-not-reply@example.com"},

            "Configures a Ping Directory Server both for SSAM access, and" +
                    " for hosting the web application.  Uses the server's own" +
                    " keystore for establishing trust of the server by SSAM.");

    exampleUsages.put(new String[]{
            "--serverRoot", "/path/to/ds/install/dir",
            "--ldapPort", "636",
            "--bindDN", "cn=Directory Manager",
            "--bindPassword", "password",
            "--useSSL",
            "--trustStorePath", "/path/to/ds/install/dir/config/keystore",
            "--peopleBaseDN", "ou=People,dc=example,dc=com",
            "--smtpServerHostname", "smtp.example.com",
            "--smtpSenderEmailAddress", "do-not-reply@example.com",
            "--noDeploy"},

            "Configures a Ping Directory Server for SSAM access, but includes" +
                    " the --noDeploy option so that setup does not" +
                    " install the SSAM application, which will be hosted by" +
                    " a Directory Proxy Server.");

//    TODO: Proxy usage hidden for now pending DS-14143
//    exampleUsages.put(new String[]{
//            "--serverRoot", "/path/to/proxy/install/dir",
//            "--ldapPort", "636",
//            "--bindDN", "cn=Directory Manager",
//            "--bindPassword", "password",
//            "--useSSL",
//            "--trustStorePath", "/path/to/proxy/install/dir/config/keystore",
//            "--peopleBaseDN", "ou=People,dc=example,dc=com" },
//
//            "Configures a Ping Directory Proxy Server for hosting SSAM.  A previous" +
//                    " invocation of this tool on the Directory Server was used to" +
//                    " configure access by SSAM, and generate the SSAM user" +
//                    " password file.");

    return exampleUsages;
  }



  // Writes a single lines to a file.
  private void writeToFile(final File file, final String line)
          throws IOException
  {
    writeToFile(file, Collections.singletonList(line));
  }



  // Writes a list of lines to a file.
  private void writeToFile(final File file, final List<String> lines)
          throws IOException
  {
    if (!file.exists())
    {
      if (!file.createNewFile())
      {
        throw new IOException("Failed to create file " + file.getCanonicalPath());
      }

      if (! StaticUtils.isWindows())
      {
        // Allow user write so files can be easily deleted if necessary.
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(Paths.get(file.getCanonicalPath()), perms);
      }
    }

    try (PrintWriter writer = new PrintWriter(file))
    {
      for (String line : lines)
      {
        writer.println(line);
      }
    }
  }



  /**
   * Returns a list of modifications that would update a source schema to
   * contain all the attributes and object classes defined in a target schema.
   *
   * @param sourceSchema   to check.
   * @param targetSchema   containing elements to be added to the source.
   * @param schemaFileName name of the file to which the server will
   *                       add the new schema elements using the X-SCHEMA-FILE
   *                       extension.
   *
   * @return a list LDAP modifications.
   */
  private static List<Modification> diffSchemas(final Schema sourceSchema,
                                                final Schema targetSchema,
                                                final String schemaFileName)
  {
    final List<Modification> modifications = new ArrayList<>();

    for (AttributeTypeDefinition def : targetSchema.getAttributeTypes())
    {
      AttributeTypeDefinition extDef = sourceSchema.getAttributeType(
              def.getNameOrOID());
      AttributeTypeDefinition defWithFile = setFile(schemaFileName, def);
      if (extDef == null || !extDef.equals(def))
      {
        modifications.add(new Modification(ModificationType.ADD,
                Schema.ATTR_ATTRIBUTE_TYPE, defWithFile.toString()));
      }
    }

    for (ObjectClassDefinition def : targetSchema.getObjectClasses())
    {
      ObjectClassDefinition extDef = sourceSchema.getObjectClass(
              def.getNameOrOID());
      ObjectClassDefinition defWithFile = setFile(schemaFileName, def);
      if (extDef == null || !extDef.equals(def))
      {
        modifications.add(
                new Modification(ModificationType.ADD, Schema.ATTR_OBJECT_CLASS,
                        defWithFile.toString()));

      }
    }

    return modifications;
  }



  /**
   * Sets the X-SCHEMA-FILE value in a map intended for use in a schema element
   * definition's extended information.
   *
   * @param file       value of X-SCHEMA-FILE; must not be {@code null}.
   * @param definition in which to place the value
   *
   * @return new definition with the X-SCHEMA-FILE extension set.
   */
  static private AttributeTypeDefinition setFile(final String file, final AttributeTypeDefinition definition)
  {
    Map<String, String[]> currExtensions = definition.getExtensions();
    Map<String, String[]> newExtensions = new LinkedHashMap<>();
    if (currExtensions != null)
    {
      newExtensions.putAll(currExtensions);
    }
    String[] extValue = {file};
    newExtensions.put("X-SCHEMA-FILE", extValue);
    return new AttributeTypeDefinition(definition.getOID(),
            definition.getNames(), definition.getDescription(),
            definition.isObsolete(), definition.getSuperiorType(),
            definition.getEqualityMatchingRule(),
            definition.getOrderingMatchingRule(),
            definition.getSubstringMatchingRule(), definition.getSyntaxOID(),
            definition.isSingleValued(), definition.isCollective(),
            definition.isNoUserModification(), definition.getUsage(),
            newExtensions);
  }



  /**
   * Sets the X-SCHEMA-FILE value in a map intended for use in a schema element
   * definition's extended information.
   *
   * @param file       value of X-SCHEMA-FILE
   * @param definition in which to place the value
   *
   * @return new definition with the X-SCHEMA-FILE extension set.
   */
  static private ObjectClassDefinition setFile(final String file,
                                               final ObjectClassDefinition definition)
  {
    Map<String, String[]> currExtensions = definition.getExtensions();
    Map<String, String[]> newExtensions = new LinkedHashMap<>();
    if (currExtensions != null)
    {
      newExtensions.putAll(currExtensions);
    }
    String[] extValue = {file};
    newExtensions.put("X-SCHEMA-FILE", extValue);
    return new ObjectClassDefinition(definition.getOID(), definition.getNames(),
            definition.getDescription(), definition.isObsolete(),
            definition.getSuperiorClasses(), definition.getObjectClassType(),
            definition.getRequiredAttributes(),
            definition.getOptionalAttributes(), newExtensions);
  }



  /**
   * Log an exception.
   */
  private void LOG(Throwable t)
  {
    if (logOutput != null)
    {
      t.printStackTrace(logOutput);
    }
  }



  /**
   * Log a message.
   */
  private void LOG(String message)
  {
    if (logOutput != null)
    {
      logOutput.append(message);
      logOutput.append("\n");
    }
  }



  /**
   * Indicates whether SSAM will be deployed during this session.  False
   * indicates that this installer is just configuring the server for SSAM
   * access.
   */
  private boolean deploySSAM()
  {
    return !noDeployArg.isPresent();
  }



  /**
   * Redirects an input stream to the installer's log stream.
   * Captures the output for the caller.
   */
  private class CommandOutputHandler extends Thread
  {
    private final Reader reader;
    private final Appendable outputBuffer;
    private final AtomicBoolean processIsRunning = new AtomicBoolean(true);

    // Exception that may occur while the process output buffer is read.
    private volatile Exception exception;


    /**
     * Constructor.
     *
     * @param inputStream  The inputStream to read from.
     * @param outputBuffer The buffer to write the inputStream contents to.
     *                     Appendable is used so that it works with both
     *                     StringBuilder and StringBuffer.
     */
    CommandOutputHandler(final InputStream inputStream,
                                final Appendable outputBuffer)
    {
      this.reader = new BufferedReader(new InputStreamReader(inputStream));
      this.outputBuffer = outputBuffer;
      this.setDaemon(true);
    }

    /**
     * This should be called after the process has exited.  Once this method
     * returns, all of the contents of the InputStream will have been placed
     * in the buffer.
     */
    void readFullyAndClose() throws InterruptedException
    {
      processIsRunning.set(false);
      this.join();
    }


    /**
     * Return any exceptions encountered while reading the process output.
     *
     * @return exception
     */
    Exception getException()
    {
      return exception;
    }


    /**
     * Handle a character output from the process.
     *
     * @param c character to append.
     * @throws IOException
     */
    void handle(char c) throws IOException
    {
      outputBuffer.append(c);
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void run()
    {
      try
      {
        // This reads one character at a time, which turns out to not be
        // too bad since the reader is buffered and we're not expecting much
        // output.  Attempts to buffer this using readLine failed because
        // the readLine didn't return after the process exited.
        StringBuilder lastLine = new StringBuilder();
        do
        {
          Thread.sleep(10);
          boolean done = false;
          while (reader.ready() && !done)
          {
            int ch = reader.read();
            if (ch == -1)   // EOF
            {
              done = true;
            }
            else
            {
              char c = (char) ch;
              handle(c);
              lastLine.append(c);
            }
          }
        }
        while (processIsRunning.get());
      }
      catch (final Exception e)
      {
        e.printStackTrace();
        exception = e;
      }
      finally
      {
        try
        {
          reader.close();
        }
        catch (final IOException ie)
        { // Ignore it.
        }
      }
    }
  }

  /**
   * Sets up a secure ldap connection with supplied secure connections arguments.
   * @param ldapPort  port to connect to the server
   * @return Established LDAPConnection object
   * @throws IOException thrown if an IO problem occurs
   * @throws LDAPException thrown if an LDAP problem occurs
   */
  private LDAPConnection setUpSecureConnection(final int ldapPort)
    throws IOException, LDAPException
  {
    LDAPConnection connection = new LDAPConnection();
    SSLUtil sslUtil = null;
    if (useSSLArg.isPresent() || useStartTLSArg.isPresent())
    {
      // Arguments will have verified one of trust-all or a trust store path
      // was specified.
      TrustManager trustManager;
      if (trustStorePathArg.isPresent())
      {
        trustManager = new TrustStoreTrustManager(trustStorePathArg.getValue().getCanonicalFile());
      }
      else
      {
        trustManager = new TrustAllTrustManager();
      }
      sslUtil = new SSLUtil(trustManager);
    }
    if (useSSLArg.isPresent())
    {
      try
      {
        SSLSocketFactory socketFactory = sslUtil.createSSLSocketFactory();
        connection = new LDAPConnection(socketFactory, localHostName, ldapPort);
      }
      catch (GeneralSecurityException gse)
      {
        throw new InstallerException(
          "Failed to setup a secure connection to the server.", gse);
      }
    }
    else
    {
      connection.connect(localHostName, ldapPort);

      if (useStartTLSArg.isPresent())
      {
        try
        {
          SSLContext sslContext = sslUtil.createSSLContext();
          ExtendedResult extendedResult = connection.processExtendedOperation(
            new StartTLSExtendedRequest(sslContext));
          if (extendedResult.getResultCode() != ResultCode.SUCCESS)
          {
            connection.close();
            throw new InstallerException("StartTLS extended operation failed.");
          }
        }
        catch (GeneralSecurityException gse)
        {
          throw new InstallerException("Failed to start TLS with server.", gse);
        }
      }
    }
    return connection;
  }
}
