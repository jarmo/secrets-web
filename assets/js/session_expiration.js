document.addEventListener("DOMContentLoaded", function() {
  function checkSession() {
    fetch("/session/status", {credentials: "same-origin", cache: "no-store"}).then(function(response) {
      if (response.status === 401) window.location.replace("/")
    }).catch(function() {})
  }

  setInterval(checkSession, 5000)
  document.addEventListener("visibilitychange", function() {
    if (!document.hidden) checkSession()
  })
})
