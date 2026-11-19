/**
 * IT Global Mail gateway.
 *
 * Deploy this Apps Script as a Web App:
 *   Execute as: Me
 *   Who has access: Anyone
 *
 * Store ITGLOBAL_MAIL_TOKEN in Script Properties.
 * The token must match the Firebase Functions secret of the same name.
 *
 * This script uses MailApp only. It cannot read or search the Gmail inbox.
 */

function doPost(e) {
  try {
    var payload = e && e.postData && e.postData.contents
      ? JSON.parse(e.postData.contents)
      : {};

    var expectedToken = PropertiesService.getScriptProperties()
      .getProperty("ITGLOBAL_MAIL_TOKEN") || "";
    var providedToken = String(payload.token || "");

    if (!constantTimeEquals(providedToken, expectedToken)) {
      return jsonResponse({ ok: false, error: "unauthorized" });
    }

    var recipient = String(payload.to || "").trim().toLowerCase();
    var subject = String(payload.subject || "").replace(/[\\r\\n]+/g, " ").trim();
    var textBody = String(payload.text || "");
    var htmlBody = String(payload.html || "");

    if (!isValidEmail(recipient) || !subject || subject.length > 250) {
      return jsonResponse({ ok: false, error: "invalid_message" });
    }

    if (textBody.length > 180000 || htmlBody.length > 180000) {
      return jsonResponse({ ok: false, error: "message_too_large" });
    }

    if (MailApp.getRemainingDailyQuota() < 1) {
      return jsonResponse({ ok: false, error: "daily_quota_exceeded" });
    }

    MailApp.sendEmail({
      to: recipient,
      subject: subject,
      body: textBody || "Уведомление IT Global",
      htmlBody: htmlBody,
      name: "IT Global"
    });

    return jsonResponse({
      ok: true,
      remaining: MailApp.getRemainingDailyQuota()
    });
  } catch (error) {
    // Do not expose recipient addresses, secrets, or provider error details.
    console.error("IT Global Mail send failed: " + String(error && error.message || error).slice(0, 180));
    return jsonResponse({ ok: false, error: "send_failed" });
  }
}

function constantTimeEquals(actual, expected) {
  if (!actual || !expected || actual.length !== expected.length) return false;
  var difference = 0;
  for (var i = 0; i < actual.length; i++) {
    difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return difference === 0;
}

function isValidEmail(value) {
  return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(value) && value.length <= 254;
}

function jsonResponse(payload) {
  return ContentService
    .createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}
