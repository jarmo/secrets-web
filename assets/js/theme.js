(function() {
  var key = "secrets-theme"
  var savedTheme = null
  var system = window.matchMedia("(prefers-color-scheme: dark)")
  try { savedTheme = localStorage.getItem(key) } catch (error) {}

  function applyTheme(theme) {
    document.documentElement.dataset.activeTheme = theme
    document.documentElement.dataset.theme = theme
    var button = document.querySelector("[data-theme-toggle]")
    if (button) {
      var next = theme === "dark" ? "light" : "dark"
      button.setAttribute("aria-label", "Switch to " + next + " mode")
      button.setAttribute("title", "Switch to " + next + " mode")
    }
  }

  if (savedTheme === "light" || savedTheme === "dark") {
    applyTheme(savedTheme)
  } else {
    applyTheme(system.matches ? "dark" : "light")
    system.addEventListener("change", function(event) {
      if (savedTheme === null) applyTheme(event.matches ? "dark" : "light")
    })
  }

  document.addEventListener("DOMContentLoaded", function() {
    applyTheme(document.documentElement.dataset.activeTheme)
  })
  document.addEventListener("click", function(event) {
    if (!event.target.closest("[data-theme-toggle]")) return
    var next = document.documentElement.dataset.activeTheme === "dark" ? "light" : "dark"
    savedTheme = next
    applyTheme(next)
    try { localStorage.setItem(key, next) } catch (error) {}
  })
})()
