document.addEventListener("DOMContentLoaded", function() {
  new App(document.querySelector("meta[name=x-csrf-token]").content, document.querySelector("meta[name=x-session-max-age-in-seconds]").content).initialize()
  Modal()
  AutoSuggest()
})
