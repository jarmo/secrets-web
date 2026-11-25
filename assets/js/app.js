function App(csrfToken, sessionMaxAgeInSeconds) {
  var session
  var tabToken
  var lastActivityAt

  this.initialize = function() {
    document.addEventListener("submit", function(event) {
      event.preventDefault()
      var form = event.target
      var method = form.getAttribute("method").toUpperCase()

      if (form.id === "login") {
        login(form)
      } else if (method === "GET") {
        var openSingle = form.dataset.openSingle === "true"
        delete form.dataset.openSingle
        request(form.action + "?" + new URLSearchParams(new FormData(form)), "GET", undefined, form.dataset.container).then(function() {
          if (!openSingle) return
          var matches = document.querySelectorAll("#secrets .secret")
          if (matches.length !== 1) return
          matches[0].open = true
          matches[0].querySelector("summary").focus()
        })
      } else {
        request(form.action, method, form.id === "logout" ? undefined : new FormData(form), form.dataset.container)
      }
    })

    document.addEventListener("click", function(event) {
      if (!tabToken || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
      var link = event.target.closest("a[href]")
      if (!link || link.target || link.hasAttribute("download")) return
      var url = new URL(link.href)
      if (url.origin !== location.origin || !accountPage(url.pathname)) return
      event.preventDefault()
      history.pushState(null, "", url.href)
      showPage(url.href)
    })

    window.addEventListener("popstate", function() {
      if (session) return location.replace("/")
      if (!tabToken) return
      if (!accountPage(location.pathname)) return location.replace("/")
      showPage(location.href)
    })

    window.addEventListener("pagehide", function() {
      if (tabToken) document.body.replaceChildren()
      tabToken = null
    })
    window.addEventListener("pageshow", function(event) {
      if (event.persisted) location.replace("/")
    })

    setInterval(checkAccount, 5000)
    document.addEventListener("visibilitychange", function() {
      if (!document.hidden) checkAccount()
    })
  }

  function newTabToken() {
    var bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    var binary = ""
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
  }

  function login(form) {
    session = new Session(document.getElementById("user").value, document.getElementById("password").value)
    return request(form.action, "POST", undefined, undefined, newTabToken())
  }

  function encodeCredentials(user, password) {
    var bytes = new TextEncoder().encode(user + ":" + password)
    var binary = ""
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
    return btoa(binary)
  }

  function accountPage(path) {
    return path === "/vaults" || path.startsWith("/vaults/") || path === "/settings"
  }

  function send(path, method, body, pendingToken) {
    var headers = {"X-Csrf-Token": csrfToken}
    if (session) headers["X-Credentials"] = encodeCredentials(session.user, session.password)
    if (pendingToken || tabToken) headers["X-Tab-Token"] = pendingToken || tabToken
    return fetch(path, {method: method, body: body, headers: headers, credentials: "same-origin", cache: "no-store"})
  }

  function showPage(path) {
    var requested = new URL(path, location.href)
    return send(requested.href, "GET").then(function(response) {
      if (!tabToken || location.pathname + location.search !== requested.pathname + requested.search) return
      var destination = new URL(response.url)
      if (!response.ok || destination.origin !== location.origin || !accountPage(destination.pathname)) return location.replace("/")
      return response.text().then(function(html) {
        if (tabToken && location.pathname + location.search === requested.pathname + requested.search) renderAccountPage(html, destination)
      })
    }).catch(function() {
      if (tabToken && location.pathname + location.search === requested.pathname + requested.search) location.replace("/")
    })
  }

  function renderAccountPage(html, url) {
    var page = new DOMParser().parseFromString(html, "text/html")
    if (!page.querySelector("main.app-shell") || !page.title) return location.replace("/")
    document.body.innerHTML = page.body.innerHTML
    document.title = page.title
    var currentVault = document.querySelector('meta[name="x-vault-alias"]')
    if (currentVault) currentVault.remove()
    var nextVault = page.querySelector('meta[name="x-vault-alias"]')
    if (nextVault) document.head.appendChild(nextVault.cloneNode(true))
    var token = page.querySelector('meta[name="x-csrf-token"]')
    if (token) csrfToken = token.content
    history.replaceState(null, "", url.pathname + url.search)
    focusFirstField()
    window.scrollTo(0, 0)
  }

  function checkAccount() {
    if (!tabToken) return
    var vault = document.querySelector('meta[name="x-vault-alias"]')
    var currentPage = location.pathname + location.search
    var path = "/session/status" + (vault ? "?vault=" + encodeURIComponent(vault.content) : "")
    send(path, "GET").then(function(response) {
      if (!tabToken || location.pathname + location.search !== currentPage) return
      if (response.status === 403) {
        history.replaceState(null, "", "/vaults")
        showPage("/vaults")
      } else if (response.status !== 204) {
        location.replace("/")
      }
    }).catch(function() {
      if (tabToken && location.pathname + location.search === currentPage) location.replace("/")
    })
  }

  function request(path, method, body, container, pendingToken) {
    var action = new URL(path, location.href).pathname
    return send(path, method, body, pendingToken).then(function(response) {
      if (response.status === 204) {
        if (action === "/login" && pendingToken) {
          tabToken = pendingToken
          session = null
          history.pushState(null, "", "/vaults")
          return showPage("/vaults")
        }
        location.replace(action === "/logout" || action === "/settings/password" ? "/" : "/vaults")
        return
      }
      if (tabToken && response.status === 401) return location.replace("/")
      if (response.redirected && !session && !tabToken) return location.assign(response.url)
      if (response.status === 401) session = null
      if (action === "/settings/password" && response.status === 400) {
        return response.text().then(function(message) { throw message })
      }
      if (!response.ok && response.status !== 401) throw "Request failed! Please try again."
      return response.text().then(function(html) {
        if (tabToken && !container) {
          var destination = new URL(response.url)
          if (destination.origin !== location.origin || !accountPage(destination.pathname)) return location.replace("/")
          renderAccountPage(html, destination)
        } else {
          var target = container ? document.querySelector(container) : document.body
          if (target) target.innerHTML = html
          if (action === "/login" && session) {
            history.pushState(null, "", "/")
            document.title = session.user + " — Secrets"
            lastActivityAt = Date.now()
            logoutAfterSessionExpiration()
          }
          focusFirstField()
        }
        lastActivityAt = Date.now()
      })
    }).catch(function(error) {
      alert(error)
      location.replace("/")
    })
  }

  function focusFirstField() {
    var first = Array.from(document.querySelectorAll("input[autofocus]")).find(function(input) { return input.offsetParent })
    if (first) first.focus()
  }

  function logoutAfterSessionExpiration() {
    setInterval(function() {
      if (Date.now() - lastActivityAt > sessionMaxAgeInSeconds * 1000) location.replace("/")
    }, 5000)
  }
}
