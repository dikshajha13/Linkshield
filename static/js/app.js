/* app.js - front-end logic for LinkShield (vanilla JavaScript, no frameworks).
   Untrusted text is ALWAYS inserted with textContent, never innerHTML,
   so a malicious URL can't inject HTML or scripts into the page. */
(function () {
  "use strict";
  var MAX_LEN = 2048;

  // Helper: create an element, optionally with a class and (safe) text.
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // Quick checks before calling the server (the server repeats them).
  function validateInput(value) {
    var v = value.trim();
    if (!v) return "Please enter a URL to scan.";
    if (v.length > MAX_LEN) return "The URL is too long (maximum " + MAX_LEN + " characters).";
    if (/\s/.test(v)) return "The URL must not contain spaces.";
    if (!/^https?:\/\//i.test(v)) return "The URL must start with http:// or https://";
    try { new URL(v); } catch (e) { return "This does not look like a valid URL."; }
    return "";
  }

  // Wrapper around fetch() that turns errors into exceptions with a readable message.
  async function api(path, options) {
    var res = await fetch(path, options);
    var data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (!res.ok || !data || data.ok === false) {
      throw new Error((data && data.error) || "Request failed (" + res.status + ").");
    }
    return data;
  }

  function section(container, title) {
    container.appendChild(el("h3", null, title));
  }

  function renderResult(container, r) {
    container.textContent = "";
    var lvl = "level-" + r.level;

    container.appendChild(el("h2", null, "Scan result"));
    container.appendChild(el("div", "url mono", r.url));

    var row = el("div", "score-row " + lvl);
    var score = el("div", "score", String(r.score));
    score.appendChild(el("small", null, " / 100"));
    row.appendChild(score);
    row.appendChild(el("span", "pill " + lvl, r.label));
    container.appendChild(row);

    var meter = el("div", "meter " + lvl);
    meter.setAttribute("role", "meter");
    meter.setAttribute("aria-valuemin", "0");
    meter.setAttribute("aria-valuemax", "100");
    meter.setAttribute("aria-valuenow", String(r.score));
    meter.setAttribute("aria-label", "Risk score " + r.score + " out of 100");
    var fill = el("div", "meter-fill");
    fill.style.width = Math.max(r.score, 2) + "%";
    meter.appendChild(fill);
    container.appendChild(meter);
    var scale = el("div", "meter-scale");
    ["0", "Low", "Medium", "High", "100"].forEach(function (t) { scale.appendChild(el("span", null, t)); });
    container.appendChild(scale);

    section(container, "Detected indicators (" + r.indicators.length + ")");
    if (!r.indicators.length) {
      container.appendChild(el("p", "muted", "No suspicious patterns were found in the URL text."));
    }
    r.indicators.forEach(function (ind) {
      var box = el("div", "finding sev-" + ind.severity);
      var t = el("div", "title");
      t.appendChild(el("span", null, ind.title));
      t.appendChild(el("span", "pts", "+" + ind.points + " pts"));
      box.appendChild(t);
      box.appendChild(el("p", null, ind.explanation));
      container.appendChild(box);
    });

    if (r.positives.length) {
      section(container, "Positive observations");
      var good = el("ul", "good");
      r.positives.forEach(function (p) { good.appendChild(el("li", null, p)); });
      container.appendChild(good);
    }

    section(container, "What you should do");
    var adv = el("ul", "advice");
    r.advice.forEach(function (a) { adv.appendChild(el("li", null, a)); });
    container.appendChild(adv);

    container.appendChild(el("p", "notice",
      r.disclaimer + " The score is a heuristic, not a confirmed probability of an attack."));
    container.hidden = false;
  }

  /* ---------------- Home page ---------------- */
  function initHome() {
    var form = document.getElementById("scan-form");
    var input = document.getElementById("url-input");
    var errorBox = document.getElementById("form-error");
    var button = document.getElementById("scan-btn");
    var result = document.getElementById("result");

    function showError(msg) { errorBox.textContent = msg; errorBox.hidden = !msg; }

    async function scan() {
      var problem = validateInput(input.value);
      showError(problem);
      if (problem) { input.focus(); return; }
      button.disabled = true;
      button.textContent = "Scanning...";
      try {
        var data = await api("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: input.value.trim() })
        });
        renderResult(result, data.result);
        result.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (err) {
        result.hidden = true;
        showError(err.message);
      } finally {
        button.disabled = false;
        button.textContent = "Scan URL";
      }
    }

    form.addEventListener("submit", function (e) { e.preventDefault(); scan(); });
    document.getElementById("example-list").addEventListener("click", function (e) {
      var chip = e.target.closest(".chip");
      if (!chip) return;
      input.value = chip.dataset.url;
      scan();
    });
  }

  /* ---------------- History page ---------------- */
  function initHistory() {
    var list = document.getElementById("history-list");
    var empty = document.getElementById("history-empty");
    var result = document.getElementById("result");

    async function load() {
      list.textContent = "";
      try {
        var data = await api("/api/history?limit=20");
        empty.hidden = data.scans.length > 0;
        data.scans.forEach(function (s) {
          var lvl = "level-" + s.risk_level;
          var item = el("div", "history-item");
          item.appendChild(el("div", "hscore " + lvl, String(s.risk_score)));
          item.appendChild(el("div", "hurl mono", s.url));
          var view = el("button", null, "View result");
          view.type = "button";
          view.addEventListener("click", async function () {
            try {
              var d = await api("/api/history/" + s.id);
              renderResult(result, d.scan.result);
              result.scrollIntoView({ behavior: "smooth", block: "start" });
            } catch (err) { alert(err.message); }
          });
          item.appendChild(view);
          var when = new Date(s.scanned_at).toLocaleString();
          var count = s.indicators.length;
          item.appendChild(el("div", "hmeta", when + " - " + s.risk_level + " risk - " +
            count + (count === 1 ? " indicator" : " indicators")));
          list.appendChild(item);
        });
      } catch (err) {
        empty.hidden = false;
        empty.textContent = "Could not load history: " + err.message;
      }
    }

    document.getElementById("clear-btn").addEventListener("click", async function () {
      if (!confirm("Delete all saved scans? This cannot be undone.")) return;
      try {
        await api("/api/history", { method: "DELETE" });
        result.hidden = true;
        load();
      } catch (err) { alert(err.message); }
    });
    load();
  }

  var page = document.body.dataset.page;
  if (page === "home") initHome();
  if (page === "history") initHistory();
})();
