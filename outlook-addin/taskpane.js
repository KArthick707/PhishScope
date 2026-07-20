/**
 * PhishScope Outlook taskpane.
 *
 * Reads the open message's full internet headers (Mailbox 1.8) and rendered
 * body via office.js, sends them to the PhishScope backend, and renders the
 * verdict. Raw MIME is not accessible from a read taskpane, so headers and
 * body travel separately to /analyze/outlook.
 */

// Configure these two values for your deployment.
var BACKEND_URL = "https://localhost:8000";
var API_KEY = ""; // must match the backend's PHISHSCOPE_API_KEY if that is set

// Same product-voice map as the Gmail add-on's VERDICT_STYLES -- keep the
// advice text in the two files in sync when editing.
var VERDICT_STYLES = {
  phishing: {
    title: "Phishing detected",
    advice: "Do not click links, open attachments, or reply. Report this email as phishing and delete it."
  },
  suspicious: {
    title: "Suspicious",
    advice: "Be careful. Verify the sender through another channel before acting on this email."
  },
  needs_review: {
    title: "Needs review",
    advice: "Signals conflict on this one. Treat links and attachments with caution."
  },
  benign_or_low_risk: {
    title: "Looks safe",
    advice: "No strong phishing indicators found. Stay alert for anything unusual."
  }
};

Office.onReady(function (info) {
  if (info.host === Office.HostType.Outlook) {
    scanCurrentMessage();
  }
});

function scanCurrentMessage() {
  var item = Office.context.mailbox.item;

  getHeaders(item)
    .then(function (headers) {
      return getBodyHtml(item).then(function (bodyHtml) {
        return { headers: headers, bodyHtml: bodyHtml };
      });
    })
    .then(function (parts) {
      var attachments = (item.attachments || []).map(function (a) {
        return { name: a.name || "", content_type: a.contentType || "" };
      });
      return callBackend(parts.headers, parts.bodyHtml, attachments);
    })
    .then(renderResult)
    .catch(function (err) {
      setStatus('<span class="error">Could not analyze this message: ' + escapeHtml(String(err)) + "</span>");
    });
}

function getHeaders(item) {
  return new Promise(function (resolve, reject) {
    item.getAllInternetHeadersAsync(function (result) {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        reject(result.error ? result.error.message : "getAllInternetHeadersAsync failed");
      }
    });
  });
}

function getBodyHtml(item) {
  return new Promise(function (resolve, reject) {
    item.body.getAsync(Office.CoercionType.Html, function (result) {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        reject(result.error ? result.error.message : "body.getAsync failed");
      }
    });
  });
}

function callBackend(headers, bodyHtml, attachments) {
  var requestHeaders = { "Content-Type": "application/json" };
  if (API_KEY) {
    requestHeaders["X-API-Key"] = API_KEY;
  }

  return fetch(BACKEND_URL.replace(/\/$/, "") + "/analyze/outlook", {
    method: "POST",
    headers: requestHeaders,
    body: JSON.stringify({
      headers: headers,
      body_html: bodyHtml,
      attachments: attachments
    })
  }).then(function (response) {
    if (!response.ok) {
      throw new Error("Backend error " + response.status);
    }
    return response.json();
  });
}

function renderResult(analysis) {
  var decision = analysis.final_decision || {};
  var verdict = decision.final_verdict || "needs_review";
  var style = VERDICT_STYLES[verdict] || VERDICT_STYLES.needs_review;

  document.getElementById("status").style.display = "none";
  document.getElementById("result").style.display = "block";

  var box = document.getElementById("verdictBox");
  box.className = "verdict verdict-" + verdict;
  document.getElementById("verdictTitle").textContent = style.title;
  document.getElementById("verdictAdvice").textContent = style.advice;

  document.getElementById("confidence").textContent = (decision.confidence != null ? decision.confidence : "?") + "%";
  document.getElementById("ruleScore").textContent = (decision.rule_score != null ? decision.rule_score : "?") + "/100";
  document.getElementById("mlProb").textContent =
    decision.ml_adjusted_probability != null ? decision.ml_adjusted_probability : "?";

  var list = document.getElementById("evidenceList");
  list.innerHTML = "";
  (analysis.evidence || []).slice(0, 5).forEach(function (item) {
    var li = document.createElement("li");
    li.textContent = item.detail;
    list.appendChild(li);
  });
  if (!list.children.length) {
    var li = document.createElement("li");
    li.textContent = "No rule-engine findings.";
    list.appendChild(li);
  }

  var mlExplanation = analysis.ml_explanation;
  if (mlExplanation && mlExplanation.top_tokens) {
    var tokens = mlExplanation.top_tokens
      .filter(function (t) { return t.direction === "toward_phishing"; })
      .slice(0, 5)
      .map(function (t) { return t.token; });
    if (tokens.length) {
      document.getElementById("tokens").textContent =
        "Words that raised suspicion: " + tokens.join(", ");
    }
  }
}

function setStatus(html) {
  var status = document.getElementById("status");
  status.style.display = "block";
  status.innerHTML = html;
}

function escapeHtml(str) {
  var div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
