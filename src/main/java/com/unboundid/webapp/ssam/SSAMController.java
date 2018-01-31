/*
 * Copyright 2015-2018 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyErrorType;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyResponseControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.HtmlUtils;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.controls.IntermediateClientRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.ConsumeSingleUseTokenExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.DeliverPasswordResetTokenExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.DeliverSingleUseTokenExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.DeliverSingleUseTokenExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.GetPasswordQualityRequirementsExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.GetPasswordQualityRequirementsExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;

/** This is the main Spring MVC controller for the Self-Service Account Manager. */
@Controller
public class SSAMController
{
  private static final Logger log = LoggerFactory
          .getLogger(SSAMController.class);
  private final static String RECAPTCHA_PARAM_NAME = "g-recaptcha-response";
  private final static String TOKEN_ID = "ssam";
  private final static String CLIENT_SESSION_ID = "SSAM";

  @Autowired
  private SSAMSettings settings;

  @Autowired
  private LDAPConnectionPool pool;

  @Autowired
  private Environment environment;

  private Schema schema;

  private DN baseDN;

  /** Get the schema. */
  @PostConstruct
  public void initializeSchema() throws LDAPException
  {
    schema = pool.getSchema();
  }

  /** Get the base DN as a DN. */
  @PostConstruct
  public void initializeBaseDN() throws LDAPException
  {
    baseDN = new DN(settings.getBaseDN());
  }

  /** Makes the HTTP request available in the model. */
  @ModelAttribute("request")
  public HttpServletRequest request(HttpServletRequest request)
  {
    return request;
  }

  /**
   * Makes the CSRF token in the specified request available in the model. This
   * can be referenced within templates that need to perform POST requests.
   *
   * @param request
   *          The HTTP request that contains the CSRF token attribute
   *
   * @return Returns the CSRF token to be put in the model
   */
  @ModelAttribute("_csrf")
  public CsrfToken csrfToken(HttpServletRequest request)
  {
    return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
  }

  /**
   * Makes the SSAM Settings (and its attributes) available
   */
  @ModelAttribute("settings")
  public SSAMSettings settings()
  {
    return settings;
  }

  /**
   * Makes whether or not the Ping authentication profile is active in the
   * model.
   */
  @ModelAttribute("pingActive")
  public boolean pingActive()
  {
    return environment.acceptsProfiles("ping-authentication");
  }

  /**
   * This is an exception handler for web application exceptions, which returns
   * a response entity created via
   * {@link WebApplicationException#toResponseEntity()}.
   *
   * @param e
   *          The exception
   *
   * @return The response entity is returned with the exception's status code
   *         and error message
   */
  @ExceptionHandler(WebApplicationException.class)
  public ResponseEntity<String> handleWebApplicationException(
          WebApplicationException e)
  {
    return e.toResponseEntity();
  }

  /** Simply return the "login" view. */
  @RequestMapping("/login")
  public String login(HttpServletRequest request)
  {
    // Get the session, creating it if necessary, to make sure that the session
    // cookie gets set on the browser.  If the user goes directly to the "login"
    // page and doesn't have a session cookie, CSRF validation will fail because
    // the token that is posted in the login form cannot be correlated with the
    // token in the session.
    request.getSession(true);
    return "login";
  }

  /**
   * Handles user view requests by getting the currently authenticated user's
   * entry, populating the model with it, and returning the "user" view.
   *
   * @param model
   *          The model
   *
   * @return The "user" view is returned upon success. Otherwise, the "error"
   *         view is returned.
   */
  @RequestMapping({ "/", "/user" })
  public String getUser(Model model)
  {
    // search for the user and put the user entry and attributes into the model
    String username = SecurityContextHolder.getContext().getAuthentication()
            .getName();
    try
    {
      Entry entry = getUserEntry();
      populateUserModel(username, entry, model);
      // insert password requirements to use in the user view
      model.addAttribute("passwordRequirements",
              getPasswordRequirements(entry.getDN()));
      return "user";
    }
    catch(LDAPException e)
    {
      // if we can't get the entry, just display the error page
      model.addAttribute("error", e.getMessage());
      return "error";
    }
  }

  /**
   * Handles user update requests when the user form is submitted by modifying
   * the currently authenticated user's entry with the values in the form.
   *
   * @param parameters
   *          The user form parameters
   * @param model
   *          The model
   *
   * @return Returns the "user" view upon success or if there was an error
   *         modifying the user, in which case the error will be displayed.
   *         Otherwise, the "error" view is returned.
   */
  @RequestMapping(value = "/user", method = RequestMethod.POST,
          consumes = APPLICATION_FORM_URLENCODED_VALUE)
  public String updateUser(@RequestParam Map<String, String> parameters,
          Model model)
  {
    String username = SecurityContextHolder.getContext().getAuthentication()
            .getName();
    Entry targetEntry = null;
    try
    {
      // get the currently authenticated user's entry and make a copy of it with
      // the provided changes
      Entry sourceEntry = getUserEntry();
      model.addAttribute("passwordRequirements",
              getPasswordRequirements(sourceEntry.getDN()));
      targetEntry = sourceEntry.duplicate();
      for(Map.Entry<String, String> e : parameters.entrySet())
      {
        // only handle attributes defined in the schema
        String attribute = e.getKey();
        if(schema.getAttributeType(attribute) != null)
        {
          // either remove the value from the entry or update it
          String value = e.getValue().trim();
          if("".equals(value))
          {
            targetEntry.removeAttribute(attribute);
          }
          else
          {
            targetEntry.setAttribute(attribute, value);
          }
        }
      }

      // get the modifications required to update the entry and apply them
      List<Modification> mods = Entry.diff(sourceEntry, targetEntry, true);
      if(!mods.isEmpty())
      {
        ModifyRequest request = new ModifyRequest(sourceEntry.getDN(), mods);
        request.addControl(getIntermediateClientRequestControl());
        pool.modify(sourceEntry.getDN(), mods);
      }
      populateUserModel(username, targetEntry, model);
      model.addAttribute("success", "User changes were successfully saved.");
    }
    catch(LDAPException e)
    {
      // if we couldn't even get the entry, something bad happened, so return
      // the error view
      model.addAttribute("error", e.getMessage());
      if(targetEntry == null)
      {
        model.addAttribute("username", username);
        return "error";
      }

      // there was some sort of error encountered, probably when trying to
      // modify the entry, so populate the model with everything needed to
      // render the "user" view
      Map<String, String> modelParameters = new HashMap<>(parameters);
      modelParameters.remove("_csrf");
      model.addAllAttributes(modelParameters);
      populateUserModel(username, targetEntry, model);
    }
    return "user";
  }

  /**
   * Handles password update AJAX requests, changing the currently authenticated
   * user's password to the specified value.
   *
   * @param currentPassword
   *          The user's current password
   * @param password
   *          The new password for the user
   *
   * @return Returns a 200 status code and empty response upon success, or an
   *         error status code and error message if there is an error
   */
  @RequestMapping(value = "/updatePassword", method = RequestMethod.POST,
          consumes = APPLICATION_FORM_URLENCODED_VALUE, produces = TEXT_PLAIN_VALUE)
  public ResponseEntity<String> updatePassword(
          @RequestParam("currentPassword") String currentPassword,
          @RequestParam("password") String password)
  {
    Control[] controls = { getIntermediateClientRequestControl(),
      new PasswordPolicyRequestControl() };
    PasswordModifyExtendedRequest request = new PasswordModifyExtendedRequest(
        null, currentPassword, password, controls);
    try
    {
      PasswordModifyExtendedResult extendedResult =
        (PasswordModifyExtendedResult)pool.processExtendedOperation(request);
      ResultCode resultCode = extendedResult.getResultCode();
      if(resultCode == ResultCode.SUCCESS)
      {
        return new ResponseEntity<>(HttpStatus.OK);
      }
      else if (resultCode == ResultCode.INVALID_CREDENTIALS)
      {
        String additionalInfo = "";
        if (extendedResult.hasResponseControl(
              PasswordPolicyResponseControl.PASSWORD_POLICY_RESPONSE_OID))
        {
          additionalInfo += "Reason: ";
          Control[] responseControls = extendedResult.getResponseControls();
          String separator = "";
          for (final Control control : responseControls)
          {
            if (control.getOID().equals(
              PasswordPolicyResponseControl.PASSWORD_POLICY_RESPONSE_OID))
            {
              final PasswordPolicyResponseControl responseControl =
                (PasswordPolicyResponseControl) control;
              additionalInfo += String.format("%s%s", separator,
                getPasswordPolicyErrorTypeMessage(responseControl.getErrorType()));
              separator = ", ";
            }
          }
        }
        else
        {
          additionalInfo = (extendedResult.getDiagnosticMessage() == null) ?
            "Please verify that your old password is correct." :
            extendedResult.getDiagnosticMessage();
        }

        // This will be returned if the "current password" is incorrect.
        return new ResponseEntity<>("Your password could not be updated. " +
          additionalInfo, HttpStatus.BAD_REQUEST);
      }
      else
      {
        return new ResponseEntity<>(resultCode + " - "
            + extendedResult.getDiagnosticMessage(), HttpStatus.BAD_REQUEST);
      }
    }
    catch(LDAPException e)
    {
      return new ResponseEntity<>(e.getMessage(),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Handles self-service delete requests by hard-deleting the current user.
   * 
   * @param session
   *         The session to be invalidated upon a successful deletion
   *
   * @return Returns the "deletion-success" view upon success, and the
   *         "user" view otherwise
   */
  @RequestMapping(value = "/deleteUser", method = RequestMethod.POST,
      consumes = APPLICATION_FORM_URLENCODED_VALUE)
  public String deleteUser(HttpSession session, Model model)
  {
    Authentication authentication = SecurityContextHolder.getContext()
            .getAuthentication();
    try 
    {
      // The current code will fail if there are child entries under the current
      // user. In order to successfully delete those accounts, a subtree delete
      // request control may be used to handle the situation.
      // At the moment, there is no need for a subtree delete request control.

      // request deletion of currently authenticated user
      Object userDetails = authentication.getPrincipal();
      
      if(userDetails instanceof LDAPUser 
          && !StringUtils.isEmpty(((LDAPUser) userDetails).getDN()))
      {
        pool.delete(((LDAPUser) userDetails).getDN());  
      }
      else 
      {
        pool.delete(getUserEntry().getDN());
      }
      // deletion successful if this is reached
      if(!pingActive())
      {
        // invalidate the session to mimic LDAP logout
        session.invalidate();
      }
      return "deletion-success";
    }
    catch (LDAPException e)
    {
      log.error(e.getDiagnosticMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
      model.addAttribute("error", "There was an error deleting the account.");
      try
      {
        populateUserModel(authentication.getName(), getUserEntry(), model);
      }
      catch(LDAPException le)
      {
        log.error("Could not populate user model", e);
      }
      return "user";
    }
  }

  /** 
   * Handles registration view requests. 
   *
   * @param request
   *        The HTTP request
   * @param model
   *        The model to be populated with a list of Password Quality 
   *        Requirements
   * @return 
   *        Returns the "register" view
   * */
  @RequestMapping(value = "/register", method = RequestMethod.GET)
  public String register(HttpServletRequest request, Model model)
  {
    // Get the session, creating it if necessary, to make sure that the session
    // cookie gets set on the browser.  If the user goes to the "register" page
    // and doesn't have a session cookie, CSRF validation will fail because the
    // token that is posted in the registration form cannot be correlated with
    // the token in the session.
    request.getSession(true);

    // insert password requirements to use in the register view
    model.addAttribute("passwordRequirements", getPasswordRequirements(null));
    return "register";
  }

  /**
   * Handles user registration AJAX requests by adding a user entry using the
   * attributes in the provided parameters and sending a one-time password to
   * the user. The user's account will be disabled until after a successful
   * consumption of the registration code provided through a single use token.
   *
   * @param parameters
   *          The parameters that contain the user attributes and
   *          reCAPTCHA (optional) code to validate
   * @param request
   *          The HTTP request
   * @param session
   *          The HTTP session, which will be populated with a "userDN"
   *          attribute
   * @param model
   *          The HTTP model, which can be populated with error messages
   *          and will be populated with the DeliverRegistrationCodeResult 
   *          "result" that contains the delivery mechanism and recipient ID 
   *
   * @return The "register" view is returned if there is an error with
   *         the reCAPTCHA or creating the user and the "registration-verify" 
   *         view is returned otherwise
   */
  @RequestMapping(value = "/register", method = RequestMethod.POST,
          consumes = APPLICATION_FORM_URLENCODED_VALUE)
  public String createUser(@RequestParam Map<String, String> parameters,
          HttpServletRequest request, HttpSession session, Model model)
  {
    try
    {
      //verify reCAPTCHA
      verifyRecaptcha(parameters);

      // construct a list of attributes for the user based on the form
      // parameters
      List<Attribute> attributes = new ArrayList<>();
      for(String objectClass : settings.getObjectClasses())
      {
        attributes.add(new Attribute("objectClass", objectClass.trim()));
      }
      attributes.add(new Attribute("ds-pwp-account-disabled", "true"));
      String namingAttributeName = settings.getNamingAttribute();
      String namingAttributeValue = null;
      for(Map.Entry<String, String> e : parameters.entrySet())
      {
        // only handle attributes that are defined in the schema
        String name = e.getKey();
        if(schema.getAttributeType(name) != null)
        {
          String value = e.getValue().trim();
          if(!value.isEmpty())
          {
            attributes.add(new Attribute(name, value));
          }
          // take note of the naming attribute value for constructing the DN
          if(name.equals(namingAttributeName))
          {
            namingAttributeValue = value;
          }
        }
      }

      // make sure that the naming attribute was found
      if(namingAttributeValue == null)
      {
        model.addAttribute("error", "A naming attribute was not provided for '" 
            + namingAttributeName + "'");
        model.addAttribute("passwordRequirements",
                getPasswordRequirements(null));
        populateRegistrationModel(parameters, model);
        return "register";
      }
      
      // create and add the user entry
      DN dn = new DN(new RDN(namingAttributeName, namingAttributeValue), baseDN);
      Entry entry = new Entry(dn, attributes);
      LDAPResult result = pool.add(entry);
      ResultCode resultCode = result.getResultCode();
      if(resultCode != ResultCode.SUCCESS)
      {
        model.addAttribute("error", resultCode + " - " 
            + result.getDiagnosticMessage());
        model.addAttribute("passwordRequirements",
                getPasswordRequirements(null));
        populateRegistrationModel(parameters, model);
        return "register";
      }
      
      // send a single use token with a registration code
      DeliverRegistrationCodeResult codeResult = deliverRegistrationCode(
              entry.getDN());
      
      // put the DN in the session
      session.setAttribute("userDN", dn.toString());
      // put the code result in the session and model
      session.setAttribute("result", codeResult);
      model.addAttribute("result", codeResult);
      
      return "registration-verify";
    }
    catch(LDAPException e)
    {
      log.error("Encountered error creating user", e);
      model.addAttribute("error", e.getMessage());
      model.addAttribute("passwordRequirements", getPasswordRequirements(null));
      populateRegistrationModel(parameters, model);
      return "register";
    }
    catch(WebApplicationException e)
    {
      log.error(e.getMessage(), e);
      // add an accessible error to the model
      model.addAttribute("error", e.getMessage());
      model.addAttribute("passwordRequirements", getPasswordRequirements(null));
      populateRegistrationModel(parameters, model);
      return "register";
    }
  }

  /**
   * Handles "verify registration code" requests by consuming the 
   * single-use-token, and then enabling the account defined by the "userDN" 
   * session attribute
   *
   * @param parameters
   *          The registration code to use when consuming the token
   * @param session
   *          The HTTP session, which is expected to contain a "userDN"
   *          attribute
   * @param model
   *          The HTTP model, which is updated with errors resulting from the
   *          consumption process of the single-use-token and/or the delivery
   *          mechanism and recipient ID of a new single-use-token
   *
   * @return Returns the "registration-verify" view if there is an error with
   *         consuming the single-use-token, and "registration-success"
   *         otherwise
   */
  @RequestMapping(value = "/verifyRegistrationCode", method = RequestMethod.POST,
      consumes = APPLICATION_FORM_URLENCODED_VALUE)
  public String verifyRegistrationCode(
          @RequestParam Map<String, String> parameters, HttpSession session,
          Model model)
  {
    try
    {
      String code = parameters.get("code");
      String userDN = (String)session.getAttribute("userDN");
      ExtendedResult result = pool.processExtendedOperation(new
          ConsumeSingleUseTokenExtendedRequest(
          userDN, TOKEN_ID, code));

      if(result.getResultCode() != ResultCode.SUCCESS)
      {
        log.error("Verification code error.");
        // add an error attribute to display an error
        model.addAttribute("error", "Failed to verify code.");
        // add the result attribute to obtain recipient ID and delivery
        // mechanism
        model.addAttribute("result", session.getAttribute("result"));
        return "registration-verify";
      }
      
      // enable the account after verifying the Single-Use-Token
      pool.modify(new ModifyRequest(userDN,
              new Modification(ModificationType.DELETE,
                      "ds-pwp-account-disabled")));
      
      //clean up the session
      session.removeAttribute("result");
      
      return "registration-success";
    } 
    catch(LDAPException e)
    {
      log.error(e.getMessage(), e);
      model.addAttribute("result", session.getAttribute("result"));
      return "registration-verify";
    }
  }

  /**
   * Handles "resend registration code" AJAX requests by sending a
   * single use token containing a registration code to the user
   * defined by the "userDN" session attribute.
   *
   * @param session
   *          The HTTP session, which is expected to contain a "userDN"
   *          attribute
   *
   * @return Returns the "deliver registration code" result, which
   *         includes the delivery mechanism and recipient ID
   *
   * @throws WebApplicationException
   *           Thrown if there is a problem delivering the registration code
   *           that is handled by "handleWebApplicationException"
   */
  @ResponseBody
  @RequestMapping(value = "/resendRegistrationCode", method = RequestMethod.POST,
          produces = APPLICATION_JSON_VALUE)
  public DeliverRegistrationCodeResult resendRegistrationCode(
          HttpSession session) throws WebApplicationException
  {
    return deliverRegistrationCode((String) session.getAttribute("userDN"));
  }

  /** Simply return the "recover-password" view. */
  @RequestMapping(value = "/recoverPassword", method = RequestMethod.GET)
  public String recoverPassword(HttpServletRequest request)
  {
    // Get the session, creating it if necessary, to make sure that the session
    // cookie gets set on the browser.  If the user goes to the "recover" page
    // and doesn't have a session cookie, CSRF validation will fail because the
    // token that is posted in the recovery form cannot be correlated with the
    // token in the session. Also, clean up the session if things were put into
    // it by a failed recovery attempt.
    HttpSession session = request.getSession(true);
    session.removeAttribute("recoveryDN");
    session.removeAttribute("useRecaptcha");
    return "recover-password";
  }

  /**
   * Handles the initial portion of the password recovery flow by searching for
   * the specified user using the configured recover password search filter, and
   * delivering a password reset token to the user using a delivery mechanism
   * chosen by the server. Any errors are swallowed and not presented to the
   * user in order to prevent phishing.
   *
   * @param parameters
   *          The form parameters, which are expected to contain "identifier"
   *          and reCAPTCHA (optional) code to validate
   * @param session
   *          The session, which will be populated with a "recoveryDN" attribute
   * @param model
   *          The model, which will be populated with an "identifier" attribute
   *          if there is a problem moving on to "recover-password-verify," and
   *          a "recaptchaError" attribute if a reCAPTCHA (optional) alert needs
   *          to be shown
   *
   * @return The "recover-password" view is returned if there is an error with
   *         the reCAPTCHA response and "recover-password-verify" view is
   *         returned otherwise
   *
   * @throws WebApplicationException
   *           Thrown if there is a problem with the reCAPTCHA (optional)
   *           response
   */
  @RequestMapping(value = "/recoverPassword", method = RequestMethod.POST,
          consumes = APPLICATION_FORM_URLENCODED_VALUE)
  public String deliverPasswordResetToken(
          @RequestParam Map<String, String> parameters, HttpSession session,
          Model model) throws WebApplicationException
  {
    String identifier = parameters.get("identifier");
    String filter = settings.getRecoverPasswordSearchFilter().replace("$0",
            identifier);
    // insert password requirements to use in the recover-password-verify view
    model.addAttribute("passwordRequirements", getPasswordRequirements(null));
    try
    {
      // verify reCAPTCHA
      verifyRecaptcha(parameters);

      // search for the user
      SearchResultEntry entry = pool.searchForEntry(settings.getBaseDN(),
              SearchScope.SUB, filter);
      if(entry == null)
      {
        // the user couldn't be found, but we don't want to alert the user in
        // order to prevent phishing
        log.info("User search using the following filter did not return any "
                + "entries:  {}", filter);
        return "recover-password-verify";
      }

      // deliver a password reset token
      String dn = entry.getDN();
      DeliverPasswordResetTokenExtendedRequest deliverPasswordResetTokenRequest =
              new DeliverPasswordResetTokenExtendedRequest(dn,
                      "Password Change Code", "Password Change Code: ", null,
                      "Password Change Code: ", null, null, new Control[0]);
      ExtendedResult result =
              pool.processExtendedOperation(deliverPasswordResetTokenRequest);
      if(result.getResultCode() != ResultCode.SUCCESS)
      {
        // just log an error since we want to prevent phishing
        log.error("Encountered error while processing "
                + "DeliverPasswordResetTokenExtendedRequest for user with "
                + "DN '{}':  {}", dn, result);
      }

      // put the DN in the session
      session.setAttribute("recoveryDN", dn);
      // set personalized password requirements to use in the
      // recover-password-verify view
      model.addAttribute("passwordRequirements", getPasswordRequirements(dn));
    }
    catch(LDAPException e)
    {
      // just log an error since we want to prevent phishing
      if(e.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED)
      {
        log.info("User search using the following filter resulted "
                + "in more than one entry being returned.  User entries must "
                + "be uniquely identifiable.  Filter:  {}", filter);
      }
      else
      {
        log.error("Encountered error trying to deliver password reset token "
                + "for user '" + identifier + "'", e);
      }
    }
    catch(WebApplicationException e)
    {
      // add an accessible error to display alert
      // if any other web application exceptions occur, we do not want to let
      // the user know to prevent phishing
      model.addAttribute("recaptchaError", true);
      // update the form to keep the UID when page refreshes
      model.addAttribute("identifier", identifier);
      return "recover-password";
    }
    return "recover-password-verify";
  }

  /**
   * Completes the password recovery flow by resetting the password using the
   * password reset token.
   *
   * @param parameters
   *          The form parameters, which are expected to contain "code" and
   *          "password" and reCAPTCHA (optional) code to validate
   * @param session
   *          The session, which is expected to be populated with a "recoveryDN"
   *          attribute and a "useRecaptcha" attribute if a reCAPTCHA (optional)
   *          needs to be shown
   * @param model
   *          The model, which will be populated with an "error" attribute if
   *          there is a problem, a "recaptchaErrorAlert" attribute if a
   *          reCAPTCHA alert needs to be shown, and a "useRecaptcha" attribute
   *          if reCAPTCHA (optional) needs to be shown
   *
   * @return The "recover-password-success" view is returned upon success. If
   *         the a password reset token wasn't previously sent to the user
   *         successfully, or there is a problem resetting the password, the
   *         "recover-password-verify" view is return with an error in the
   *         model.
   *
   * @throws WebApplicationException
   *           Thrown if there is a problem with the reCAPTCHA (optional)
   *           response
   */
  @RequestMapping(value = "/resetPassword", method = RequestMethod.POST,
          consumes = APPLICATION_FORM_URLENCODED_VALUE)
  public String resetPassword(@RequestParam Map<String, String> parameters,
          HttpSession session, Model model)
          throws WebApplicationException
  {
    boolean useRecaptcha = session.getAttribute("useRecaptcha") != null;
    // checks if the session needs a reCAPTCHA
    model.addAttribute("useRecaptcha", useRecaptcha);

    // if there is no recovery DN in the session, the user didn't have a token
    // successfully sent to them, so go back to the "verify" page with an error
    String userDN = (String) session.getAttribute("recoveryDN");
    model.addAttribute("passwordRequirements", getPasswordRequirements(null));
    if(userDN == null)
    {
      model.addAttribute("error", "A password reset token was not "
              + "successfully delivered to the user.");
      return "recover-password-verify";
    }

    try
    {
      // if the session uses a reCAPTCHA, verify the reCAPTCHA
      if(useRecaptcha)
      {
        verifyRecaptcha(parameters);
      }

      String code = parameters.get("code");
      String newPassword = parameters.get("password");
      ExtendedResult result = pool.processExtendedOperation(
              new PasswordModifyExtendedRequest(userDN, code, newPassword));
      if(result.getResultCode() != ResultCode.SUCCESS)
      {
        log.error("Resetting password for user '" + userDN + "' failed: " +
          result.getResultString());
        model.addAttribute("error", result.getResultString());
        session.setAttribute("useRecaptcha", true);
        model.addAttribute("useRecaptcha", true);

        return "recover-password-verify";
      }
      session.removeAttribute("recoveryDN");
      session.removeAttribute("useRecaptcha");
      return "recover-password-success";
    }
    catch(LDAPException e)
    {
      // there was some problem resetting the password, so go back to the
      // "verify" page with an error
      log.error("Encountered exception resetting password for user '" + userDN
              + "'", e);
      model.addAttribute("error", e.getMessage());

      // adds reCAPTCHA for the session to prevent brute forcing the
      // verification code
      session.setAttribute("useRecaptcha", true);
      // adds an accessible model attribute for the reCAPTCHA
      // needed to display reCAPTCHA right after the first invalid code
      model.addAttribute("useRecaptcha", true);

      return "recover-password-verify";
    }
    catch(WebApplicationException e)
    {
      log.error(e.getMessage());
      // display the error alert
      model.addAttribute("error", e.getMessage());
      return "recover-password-verify";
    }
  }
  
  /**
   * Handles the retrieval of password requirements from the Directory Server
   * 
   * @param dn
   *         The dn for the entry for which to retrieve the password 
   *         requirements from. May be empty or null. If null, retrieve the
   *         default password requirements from the server
   * 
   * @return Returns a List&lt;PasswordQualityRequirement&gt; of current
   *         Password Quality Requirements in the DS Password Policy
   */
  public List<PasswordQualityRequirement> getPasswordRequirements(String dn)
  {
    List<PasswordQualityRequirement> pqRequirements = new ArrayList<>();
    try
    {
      GetPasswordQualityRequirementsExtendedRequest extendedRequest;
      if(StringUtils.isEmpty(dn))
      {
        extendedRequest = GetPasswordQualityRequirementsExtendedRequest
            .createAddWithDefaultPasswordPolicyRequest();
      }
      else 
      {
        extendedRequest = GetPasswordQualityRequirementsExtendedRequest
            .createSelfChangeForSpecifiedUserRequest(dn);
      }
      GetPasswordQualityRequirementsExtendedResult result =
          (GetPasswordQualityRequirementsExtendedResult)
              pool.processExtendedOperation(extendedRequest);
      pqRequirements = result.getPasswordRequirements();
    }
    catch (LDAPException e)
    {
      log.error("Failed to retrieve password requirements.", e);
    }
    return pqRequirements;
  }

  /**
   * Searches for and returns the entry for the currently authenticated user.
   *
   * @return The user entry is returned
   *
   * @throws LDAPException
   *           Thrown if there is a problem getting the entry, or if the entry
   *           returned is null
   */
  private Entry getUserEntry() throws LDAPException
  {
    Authentication authentication = SecurityContextHolder.getContext()
        .getAuthentication();
    Object userDetails = authentication.getPrincipal();
    SearchRequest request;
   
    if(userDetails instanceof LDAPUser)
    {
      request = new SearchRequest(((LDAPUser) userDetails).getDN(),
          SearchScope.BASE, "(objectClass=*)");
    }
    else
    {
      request = new SearchRequest(settings.getBaseDN(), SearchScope.SUB,
          Filter.createEqualityFilter(settings.getNamingAttribute(),
              authentication.getName()));
    }
    request.addControl(getIntermediateClientRequestControl());
    Entry entry = pool.searchForEntry(request);
    
    if(entry == null)
    {
      throw new LDAPException(ResultCode.NO_SUCH_OBJECT,
              "Entry search returned null.");
    }
    return entry;
  }

  /**
   * Populates the provided model with the specified user name and user
   * entry/attributes.
   */
  private void populateUserModel(String username, Entry entry, Model model)
  {
    model.addAttribute("username", username);
    for(Attribute attribute : entry.getAttributes())
    {
      model.addAttribute(attribute.getName(), HtmlUtils.htmlEscape(attribute.getValue()));
    }
    model.addAttribute("entry", entry);
  }

  /** Populates the provided model with the specified parameters. */
  private void populateRegistrationModel(Map<String, String> parameters,
          Model model)
  {
    for(Map.Entry<String, String> parameter : parameters.entrySet())
    {
      // handle all parameters except the password
      String name = parameter.getKey();
      if(!name.equals("userPassword") && !name.equals("_csrf"))
      {
        String value = parameter.getValue().trim();
        if(!value.isEmpty())
        {
          model.addAttribute(name, HtmlUtils.htmlEscape(value));
        }
      }
    }
  }

  /**
   * Constructs and sends a "deliver registration code" extended request for the
   * user with the provided DN. The server will choose the delivery mechanism
   * to use, which is governed by the order of delivery mechanisms registered
   * with the single-use-token extended operation handler and the optional
   * "ds-auth-preferred-otp-delivery-mechanism" attribute in the user's entry.
   *
   * @param userDN
   *          The DN of the user to use when sending the request
   *
   * @return Returns the "deliver registration code" result, which includes
   *         the delivery mechanism and recipient ID
   *
   * @throws WebApplicationException
   *           Thrown if there is an error delivering the registration code
   */
  private DeliverRegistrationCodeResult deliverRegistrationCode(String userDN)
          throws WebApplicationException
  {
    try
    {
      DeliverSingleUseTokenExtendedRequest deliverSingleUseTokenRequest =
          new DeliverSingleUseTokenExtendedRequest(
              userDN, TOKEN_ID, null,
              settings.getMessageSubject(),
              settings.getFullTextBeforeToken(),
              settings.getFullTextAfterToken(),
              settings.getCompactTextBeforeToken(),
              settings.getCompactTextAfterToken(),
              null, true, true, true, true
          );
      DeliverSingleUseTokenExtendedResult result = (DeliverSingleUseTokenExtendedResult)
          pool.processExtendedOperation(deliverSingleUseTokenRequest);
      ResultCode resultCode = result.getResultCode();

      if(resultCode == ResultCode.SUCCESS)
      {
        return new DeliverRegistrationCodeResult(result);
      }
      else
      {
        throw new WebApplicationException(HttpStatus.BAD_REQUEST, resultCode
                + " - " + result.getDiagnosticMessage());
      }
    }
    catch(LDAPException e)
    {
      log.error("Could not deliver registration code for user with userDN '"
              + userDN + "'", e);
      throw new WebApplicationException(HttpStatus.INTERNAL_SERVER_ERROR,
              e.getMessage());
    }
  }

  /**
   * Verify POSTed reCAPTCHA.
   *
   * @param parameters The POSTed params that include the reCAPTCHA code to
   *                   validate
   *
   * @throws WebApplicationException
   *           Thrown if there is an unknown internal server error or if there
   *           is a problem with the reCAPTCHA (optional) response
   */
  private void verifyRecaptcha(Map<String, String> parameters)
          throws WebApplicationException
  {
    // return if reCAPTCHA is not enabled
    if(!settings.isRecaptchaEnabled())
    {
      return;
    }

    // retrieve the reCAPTCHA widget response
    String value = parameters.get(RECAPTCHA_PARAM_NAME);

    // call the service
    MultiValueMap<String, String> args = new LinkedMultiValueMap<>();
    args.add("secret", settings.getRecaptchaSecretKey());
    args.add("response", value);
    RestTemplate restTemplate = new RestTemplate();
    try
    {
      ReCaptchaResponse response =
          restTemplate.postForObject(
            "https://www.google.com/recaptcha/api/siteverify",
            args,
            ReCaptchaResponse.class
          );

      // was the response invalid?
      if (!response.success)
      {
        throw new WebApplicationException(HttpStatus.FORBIDDEN,
                response.displayErrorMessages());
      }
    }
    catch (Exception ex)
    {
      // unknown error
      log.error("Error occurred after attempt to get a response during "
              + "CAPTCHA: " + ex.getMessage(), ex);
      throw new WebApplicationException(HttpStatus.INTERNAL_SERVER_ERROR,
              ex.getMessage());
    }
  }

  /**
   * Returns an intermediate client request control using the authzId of the 
   * currently authenticated user.
   *
   * @return  an IntermediateClientRequestControl using the authorizationID of
   * the currently authenticated user
   */
  private IntermediateClientRequestControl getIntermediateClientRequestControl()
  {
    Authentication authentication = SecurityContextHolder.getContext()
        .getAuthentication();
    Object userDetails = authentication.getDetails();
    String authzId = userDetails instanceof LDAPUser ?
        ((LDAPUser) userDetails).getAuthzID() :
        "u:" + authentication.getName();
    return new IntermediateClientRequestControl(null, null, null, authzId,
        CLIENT_SESSION_ID, null, null);
  }

  /**
   * Returns a display message for a password policy error type.
   *
   * @param errorType  password policy error type message to request.
   * @return String with display message for requested password policy error type.
   */
  private String getPasswordPolicyErrorTypeMessage(PasswordPolicyErrorType errorType)
  {
    switch (errorType)
    {
      case PASSWORD_EXPIRED:
        return "password is expired";

      case ACCOUNT_LOCKED:
        return "account is locked or disabled";

      case CHANGE_AFTER_RESET:
        return "password must be changed before any other operation " +
          "will be allowed";

      case PASSWORD_MOD_NOT_ALLOWED:
        return "password changes are not allowed";

      case MUST_SUPPLY_OLD_PASSWORD:
        return "must provide the current password when attempting " +
          "to set a new one";

      case INSUFFICIENT_PASSWORD_QUALITY:
        return "proposed password is too weak to be acceptable";

      case PASSWORD_TOO_SHORT:
        return "proposed password is too short";

      case PASSWORD_TOO_YOUNG:
        return "password cannot be changed because the previous " +
          "password change was too recent";

      case PASSWORD_IN_HISTORY:
        return "proposed password cannot be the same as the current " +
          "password or any password in the password history";

      default:
        log.warn("Missing display message for password policy errorType '" +
          errorType.toString() + "'");
        return errorType.toString();
    }
  }

  /**
   * Simple model for encapsulating response from the reCAPTCHA service.
   */
  @JsonIgnoreProperties(ignoreUnknown=true)
  private static class ReCaptchaResponse implements Serializable
  {
    private static final long serialVersionUID = 8505145164400678294L;
    private static final HashMap<String, String> codesMap = getMap();

    /**
     * Constructs a user friendly code HashMap.
     */
    private static HashMap<String,String> getMap()
    {
      HashMap<String, String> codes = new HashMap<>();

      codes.put("missing-input-secret","secret parameter is missing.");
      codes.put("invalid-input-secret","secret parameter is invalid or malformed.");
      codes.put("missing-input-response","response parameter is missing.");
      codes.put("invalid-input-response","response parameter is invalid or malformed.");

      return codes;
    }

    /**
     * Whether or not the request was successful.
     */
    public boolean success;

    /**
     * Error codes associated with the response, if any.
     */
    @JsonProperty("error-codes")
    public String[] errorCodes;

    /**
     * {@inheritDoc}
     */
    protected void toString(final StringBuilder buffer)
    {
      buffer.append("ReCaptchaResponse(success='");
      buffer.append(success);
      buffer.append("', errorCodes=[");
      buffer.append(Arrays.toString(errorCodes));
      buffer.append(']');
      buffer.append("')");
    }

    /**
     * For displaying user friendly error codes/alerts.
     */
    public String displayErrorMessages()
    {
      String errorMessage = "";

      for(String s : errorCodes)
      {
        errorMessage += "The reCAPTCHA " + codesMap.get(s) + " ";
      }

      return errorMessage;
    }
  }
}
