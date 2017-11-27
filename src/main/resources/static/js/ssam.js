/**
 * Shows either a success or error alert with the specified message in the
 * provided alert container.
 *
 * @param alertContainer A jQuery object for the div that will contain the alert
 * @param error A boolean indicating whether this is an error or success alert
 * @param message The alert message
 */
function showAlert(alertContainer, error, message) {
  alertContainer.html('<div class="alert alert-' + (error ? "danger" : "success") + ' alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button><span>' + message + '</div>');
}

/**
 * Closes the alerts contained in the provided alert container.
 *
 * @param alertContainer A jQuery object for the div that contains the alerts
 */
function closeAlerts(alertContainer) {
  alertContainer.find("div.alert").alert("close");
}

/**
 * Verifies that the required inputs in the specified form have values,
 * decorating any missing inputs appropriately and displaying an error alert
 * indicating the missing fields.
 *
 * @param form The form to check the inputs in
 * @param errorAlertContainer A jQuery object for the div that contains error alerts
 * @param successAlertContainer An optional jQuery object for the div that contains success alerts
 * @returns {Boolean} Returns true if all required fields are present
 */
function verifyRequiredInputs(form, errorAlertContainer, successAlertContainer) {
  var required = new Array();
  closeAlerts(errorAlertContainer);
  form.find(".has-error").removeClass("has-error");
  form.find(":input[required]").each(function() {
    if (this.value.trim() === "") {
      $(this).parent().addClass("has-error");
      // use either the field's placeholder or its label's value
      var name = this.placeholder;
      if (name === "" || name === undefined) {
        name = $('label[for="' + $(this).attr("name") + '"]').text();
      }
      required.push(name);
    }
  });

  // display alerts, if needed
  if (required.length > 0) {
    if (successAlertContainer) {
      closeAlerts(successAlertContainer);
    }
    showAlert(errorAlertContainer, true, "The following fields are required:  " + required.join(', '));
    return false;
  }
  return true;
}

/**
 * Returns the verification code of the form.
 *
 * @returns {var} Returns the verification code
 */
function getVerificationCode() {
  var code = "";
  $('.code').each(function() {
      code = code.concat($(this).val().trim());
  });
  return code;
}

/**
 * Adds an event listener to elements with class "code" in order to auto-focus
 * to the next element with class "code" after the current element's value is
 * changed.
 */
function autofocusCodeInputs() {
  $(".code").first().focus();
  // auto-focus to next code input
  $(".code").keyup(function() {
    var el = $(this);
    if (el.val().length >= 1) {
      el.next(".code").focus();
    }
  });
}