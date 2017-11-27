/*
 * Copyright 2015-2017 Ping Identity Corporation
 *
 * All Rights Reserved.
 */
package com.unboundid.webapp.ssam;

import com.unboundid.ldap.sdk.unboundidds.extensions.DeliverSingleUseTokenExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.DeliverOneTimePasswordExtendedResult;

/**
 * Encapsulates information about the result of a specified
 * extended operation.
 */
public class DeliverRegistrationCodeResult
{
  private String deliveryMechanism;
  private String recipientID;

  /** 
   * Creates a new instance using the specified extended operation result.
   * */
  public DeliverRegistrationCodeResult(
      DeliverSingleUseTokenExtendedResult result)
  {
    this.deliveryMechanism = result.getDeliveryMechanism();
    this.recipientID = result.getRecipientID();
  }

  /** 
   * Creates a new instance using the specified extended operation result. 
   * */
  public DeliverRegistrationCodeResult(
      DeliverOneTimePasswordExtendedResult result)
  {
    this.deliveryMechanism = result.getDeliveryMechanism();
    this.recipientID = result.getRecipientID();
  }

  /** 
   * Returns the delivery mechanism that was used to deliver the
   * registration code. 
   * */
  public String getDeliveryMechanism()
  {
    return deliveryMechanism;
  }

  /**
   * Returns the recipient ID that the registration code was delivered to
   * (e.g. phone number or email address).
   */
  public String getRecipientID()
  {
    return recipientID;
  }
}
