document.addEventListener("DOMContentLoaded", function() {
  var vault = document.querySelector('meta[name="x-vault-alias"]')
  var statusURL = "/session/status"
  if (vault) statusURL += "?vault=" + encodeURIComponent(vault.content)

  function checkSession() {
    fetch(statusURL, {credentials: "same-origin", cache: "no-store"}).then(function(response) {
      if (response.status === 401) window.location.replace("/")
      else if (response.status === 403) window.location.replace("/vaults")
    }).catch(function() {})
  }

  setInterval(checkSession, 5000)
  document.addEventListener("visibilitychange", function() {
    if (!document.hidden) checkSession()
  })
})
