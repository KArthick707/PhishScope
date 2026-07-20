/**
 * PhishScope Gmail Add-on.
 *
 * Contextual trigger: when the user opens a message, fetch it in raw RFC822
 * form via the Gmail REST API (using the add-on's per-message access token),
 * send it to the PhishScope backend for full rule+ML analysis, and render the
 * verdict as a sidebar card.
 *
 * Script Properties (Project Settings -> Script Properties):
 *   PHISHSCOPE_BACKEND_URL  e.g. https://phishscope.example.com  (required)
 *   PHISHSCOPE_API_KEY      matches the backend's PHISHSCOPE_API_KEY (optional)
 */

// Per-verdict presentation. This is the product voice of the add-on -- the
// one place that decides what a non-technical user is told to DO for each
// verdict. Tune freely without touching any logic.
var VERDICT_STYLES = {
  phishing: {
    title: "Phishing detected",
    color: "#b91c1c",
    icon: "https://www.gstatic.com/images/icons/material/system/1x/report_red_24dp.png",
    advice: "Do not click links, open attachments, or reply. Report this email as phishing and delete it."
  },
  suspicious: {
    title: "Suspicious",
    color: "#b45309",
    icon: "https://www.gstatic.com/images/icons/material/system/1x/warning_amber_24dp.png",
    advice: "Be careful. Verify the sender through another channel before acting on this email."
  },
  needs_review: {
    title: "Needs review",
    color: "#1d4ed8",
    icon: "https://www.gstatic.com/images/icons/material/system/1x/help_googblue_24dp.png",
    advice: "Signals conflict on this one. Treat links and attachments with caution."
  },
  benign_or_low_risk: {
    title: "Looks safe",
    color: "#15803d",
    icon: "https://www.gstatic.com/images/icons/material/system/1x/check_circle_googgreen_24dp.png",
    advice: "No strong phishing indicators found. Stay alert for anything unusual."
  }
};

function onGmailMessageOpen(e) {
  try {
    var messageId = e.gmail.messageId;
    var accessToken = e.gmail.accessToken;

    var rawBase64 = fetchRawMessage_(messageId, accessToken);
    var analysis = callBackend_(rawBase64);

    return [buildVerdictCard_(analysis)];
  } catch (err) {
    return [buildErrorCard_(String(err))];
  }
}

/** Fetches the open message as base64url RFC822 via the Gmail REST API. */
function fetchRawMessage_(messageId, accessToken) {
  var url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" +
            encodeURIComponent(messageId) + "?format=raw";

  var response = UrlFetchApp.fetch(url, {
    headers: { Authorization: "Bearer " + accessToken },
    muteHttpExceptions: true
  });

  if (response.getResponseCode() !== 200) {
    throw new Error("Gmail API error " + response.getResponseCode());
  }

  return JSON.parse(response.getContentText()).raw;
}

/** Sends the raw message to the PhishScope backend and returns the analysis. */
function callBackend_(rawBase64) {
  var props = PropertiesService.getScriptProperties();
  var backendUrl = props.getProperty("PHISHSCOPE_BACKEND_URL");
  if (!backendUrl) {
    throw new Error("PHISHSCOPE_BACKEND_URL script property is not set.");
  }

  var headers = {};
  var apiKey = props.getProperty("PHISHSCOPE_API_KEY");
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  var response = UrlFetchApp.fetch(backendUrl.replace(/\/$/, "") + "/analyze/raw", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ raw_base64: rawBase64 }),
    headers: headers,
    muteHttpExceptions: true
  });

  if (response.getResponseCode() !== 200) {
    throw new Error("PhishScope backend error " + response.getResponseCode());
  }

  return JSON.parse(response.getContentText());
}

function buildVerdictCard_(analysis) {
  var decision = analysis.final_decision || {};
  var verdict = decision.final_verdict || "needs_review";
  var style = VERDICT_STYLES[verdict] || VERDICT_STYLES.needs_review;

  var header = CardService.newCardHeader()
    .setTitle(style.title)
    .setSubtitle("Confidence: " + (decision.confidence || "?") + "%")
    .setImageUrl(style.icon);

  var verdictSection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      "<b><font color=\"" + style.color + "\">" + style.title + "</font></b><br>" + style.advice
    ))
    .addWidget(CardService.newTextParagraph().setText(
      decision.reason || ""
    ));

  var detailSection = CardService.newCardSection()
    .setHeader("Why")
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  detailSection.addWidget(CardService.newKeyValue()
    .setTopLabel("Rule score")
    .setContent(String(decision.rule_score != null ? decision.rule_score : "?") + "/100"));

  detailSection.addWidget(CardService.newKeyValue()
    .setTopLabel("ML phishing probability")
    .setContent(String(
      decision.ml_adjusted_probability != null ? decision.ml_adjusted_probability : "?"
    )));

  var evidence = analysis.evidence || [];
  for (var i = 0; i < Math.min(evidence.length, 5); i++) {
    detailSection.addWidget(CardService.newTextParagraph()
      .setText("• " + evidence[i].detail));
  }

  var mlExplanation = analysis.ml_explanation;
  if (mlExplanation && mlExplanation.top_tokens && mlExplanation.top_tokens.length) {
    var tokens = mlExplanation.top_tokens
      .filter(function (t) { return t.direction === "toward_phishing"; })
      .slice(0, 5)
      .map(function (t) { return t.token; });
    if (tokens.length) {
      detailSection.addWidget(CardService.newTextParagraph()
        .setText("<i>Words that raised suspicion: " + tokens.join(", ") + "</i>"));
    }
  }

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(verdictSection)
    .addSection(detailSection)
    .build();
}

function buildErrorCard_(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("PhishScope unavailable"))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        "Could not analyze this message.<br><br><font color=\"#6b7280\">" + message + "</font>"
      )
    ))
    .build();
}
