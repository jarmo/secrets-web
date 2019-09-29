function App(csrfToken, sessionMaxAgeInSeconds) {
  var session

  this.initialize = function() {
    document.addEventListener("submit", function(event) {
      event.preventDefault()
      var form = event.target

      if (form.id === "login") {
        login(form).then(logoutAfterSessionExpiration)
      } else if (form.id == "logout") {
        window.location.reload()
      } else {
        request(form.action, form.method, new FormData(form))
      }
    })
  }

  function login(form) {
    session = new Session(document.getElementById("user").value, document.getElementById("password").value)
    return request(form.action, form.method)
  }

  function request(path, method, data) {
    return fetch(path, {
      method: method,
      body: data,
      headers: {
        "Authorization": "Bearer " + btoa(session.user + ":" + session.password),
        "X-Csrf-Token": csrfToken
      }
    }).then(function(response) {
      return response.text()
    }).then(function(body) {
      document.body.innerHTML = body
    })
  }

  var logoutTimeoutId

  function logoutAfterSessionExpiration() {
    clearTimeout(logoutTimeoutId)
    logoutTimeoutId = setTimeout(function() { window.location.reload() }, sessionMaxAgeInSeconds * 1000)
  }
}
