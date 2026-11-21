function App(csrfToken, sessionMaxAgeInSeconds) {
  var session

  this.initialize = function() {
    document.addEventListener("submit", function(event) {
      event.preventDefault()
      var form = event.target
      var formMethod = form.getAttribute("method").toUpperCase()

      if (form.id === "login") {
        login(form)
      } else if (form.id === "logout") {
        request(form.action, "POST")
      } else if (formMethod === "GET") {
        var openSingle = form.dataset.openSingle === "true"
        delete form.dataset.openSingle
        get(form.action, new FormData(form), form.dataset.container).then(function() {
          if (openSingle) {
            var matches = document.querySelectorAll("#secrets .secret")
            if (matches.length === 1) {
              matches[0].open = true
              matches[0].querySelector("summary").focus()
            }
          }
        })
      } else {
        request(form.action, formMethod, new FormData(form), form.dataset.container)
      }
    })
  }

  function login(form) {
    session = new Session(document.getElementById("user").value, document.getElementById("password").value)
    return request(form.action, "POST").then(function() {
      if (session) logoutAfterSessionExpiration()
    })
  }

  function encodeCredentials(user, password) {
    var bytes = new TextEncoder().encode(user + ":" + password)
    var binary = ""
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
    return btoa(binary)
  }

  function get(path, data, container) {
    return request([path, new URLSearchParams(data)].join("?"), "GET", undefined, container)
  }

  function request(path, method, body, container) {
    var headers = {"X-Csrf-Token": csrfToken}
    if (session) headers["X-Credentials"] = encodeCredentials(session.user, session.password)

    return fetch(path, {method: method, body: body, headers: headers}).then(function(response) {
      if (response.status === 204) {
        session = null
        window.location.assign(path.endsWith("/logout") || path === "/settings/password" ? "/" : "/vaults")
        return null
      }
      if (response.redirected && !session) {
        window.location.assign(response.url)
        return null
      }
      if (response.status === 401) session = null
      if (path === "/settings/password" && response.status === 400) {
        return response.text().then(function(message) { throw message })
      }
      if (!response.ok && response.status !== 401) throw "Request failed! Please try again."
      return response.text()
    }).then(function(body) {
      if (body === null) return
      var resultContainer = container ? document.querySelector(container) : document.body
      resultContainer.innerHTML = body
      var firstVisibleAutofocusableField = Array
        .from(resultContainer.querySelectorAll("input[autofocus]"))
        .find(input => input.offsetParent)

      if (firstVisibleAutofocusableField) firstVisibleAutofocusableField.focus()
    }).then(setLastActivityAt)
      .catch(function(error) {
      alert(error)
      location.reload()
    })
  }

  var lastActivityAt

  function setLastActivityAt() {
    lastActivityAt = Date.now()
  }

  function logoutAfterSessionExpiration() {
    var sessionMaxAgeInMillis = sessionMaxAgeInSeconds * 1000
    setInterval(function() {
      if (Date.now() - lastActivityAt > sessionMaxAgeInMillis) window.location.reload()
    }, 5 * 1000)
  }
}
