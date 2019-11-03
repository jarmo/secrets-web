function App(csrfToken, sessionMaxAgeInSeconds) {
  var session

  this.initialize = function() {
    document.addEventListener("submit", function(event) {
      event.preventDefault()
      var form = event.target
      var formMethod = form.getAttribute("method").toUpperCase()

      if (form.id === "login") {
        login(form).then(logoutAfterSessionExpiration)
      } else if (form.id == "logout") {
        window.location.reload()
      } else if (formMethod === "GET") {
        get(form.action, new FormData(form))
      } else {
        request(form.action, formMethod, new FormData(form))
      }
    })
  }

  function login(form) {
    session = new Session(document.getElementById("user").value, document.getElementById("password").value)
    return request(form.action, "POST")
  }

  function get(path, data) {
    return request([path, new URLSearchParams(data)].join("?"), "GET")
  }

  function request(path, method, body) {
    return fetch(path, {
      method: method,
      body: body,
      headers: {
        "X-Credentials": btoa(session.user + ":" + session.password),
        "X-Csrf-Token": csrfToken
      }
    }).then(function(response) {
      if (!response.ok && response.status !== 401) throw "Request failed! Please try again."

      return response.text()
    }).then(function(body) {
      document.body.innerHTML = body
    }).catch(function(error) {
      alert(error)
      location.reload()
    })
  }

  var logoutTimeoutId

  function logoutAfterSessionExpiration() {
    clearTimeout(logoutTimeoutId)
    logoutTimeoutId = setTimeout(function() { window.location.reload() }, sessionMaxAgeInSeconds * 1000)
  }
}
