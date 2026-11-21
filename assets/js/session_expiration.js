document.addEventListener("DOMContentLoaded", function() {
  var vault = document.querySelector('meta[name="x-vault-alias"]')
  var statusURL = "/session/status"
  if (vault) statusURL += "?vault=" + encodeURIComponent(vault.content)
  var leaving = false

  function navigateAway(path) {
    if (leaving) return
    leaving = true
    document.body.replaceChildren()
    try {
      window.location.replace(path)
    } catch (_) {}
  }

  function checkSession() {
    if (leaving) return
    fetch(statusURL, {credentials: "same-origin", cache: "no-store"}).then(function(response) {
      if (response.status === 401) navigateAway("/")
      else if (response.status === 403) navigateAway("/vaults")
      else if (response.status !== 204) navigateAway("/")
    }).catch(function() {
      navigateAway("/")
    })
  }

  setInterval(checkSession, 5000)
  document.addEventListener("visibilitychange", function() {
    if (!document.hidden) checkSession()
  })
})
