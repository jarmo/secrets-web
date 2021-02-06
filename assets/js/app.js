function App(csrfToken, sessionMaxAgeInSeconds) {
  var session

  this.initialize = function() {
    document.addEventListener("submit", function(event) {
      event.preventDefault()
      var form = event.target
      var formMethod = form.getAttribute("method").toUpperCase()

      if (form.id === "login") {
        login(form)
      } else if (form.id == "logout") {
        window.location.reload()
      } else if (formMethod === "GET") {
        get(form.action, new FormData(form), form.dataset.container)
      } else {
        request(form.action, formMethod, new FormData(form), form.dataset.container)
      }
    })
  }

  function login(form) {
    session = new Session(document.getElementById("user").value, document.getElementById("password").value)
    return request(form.action, "POST").then(logoutAfterSessionExpiration)
  }

  function get(path, data, container) {
    return request([path, new URLSearchParams(data)].join("?"), "GET", undefined, container)
  }

  function request(path, method, body, container) {
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
