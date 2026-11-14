// The test site in Italian or English, as the lab's other pages: IT|EN, remembered in this browser.
(function () {
  var lang = "it";
  try { var s = localStorage.getItem("lang"); lang = s === "en" ? "en" : s === "it" ? "it" : ((navigator.language || "").slice(0, 2) === "en" ? "en" : "it"); } catch (e) { }
  function apply() {
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-" + lang + "]").forEach(function (el) { el.textContent = el.getAttribute("data-" + lang); });
    document.title = document.title.replace(lang === "en" ? "sito di prova" : "test site", lang === "en" ? "test site" : "sito di prova")
      .replace(lang === "en" ? "Contatti" : "Contact", lang === "en" ? "Contact" : "Contatti");
    document.querySelectorAll("[data-lang]").forEach(function (a) { a.style.fontWeight = a.getAttribute("data-lang") === lang ? "bold" : "normal"; });
  }
  document.querySelectorAll("[data-lang]").forEach(function (a) {
    a.addEventListener("click", function (e) { e.preventDefault(); lang = a.getAttribute("data-lang"); try { localStorage.setItem("lang", lang); } catch (x) { } apply(); });
  });
  apply();
})();
