function AutoSuggest() {
  var search = defer(function(event) {
    var target = event.target
    if (target.id === "filter") {
      var form = target.closest("form")
      form.querySelector("input[type='submit']").click()
    }
  })

  document.addEventListener('input', function(event) {
    if (event.target.id === "vault-filter") {
      var filter = event.target.value.toLowerCase()
      document.querySelectorAll("#vaults .vault").forEach(function(vault) {
        vault.hidden = !vault.textContent.toLowerCase().includes(filter)
      })
    } else {
      search(event)
    }
  })

  document.addEventListener('keydown', function(event) {
    if (event.key !== "Enter") return

    if (event.target.id === "vault-filter") {
      event.preventDefault()
      var matches = document.querySelectorAll("#vaults .vault:not([hidden]) a")
      if (matches.length === 1) window.location.assign(matches[0].href)
    } else if (event.target.id === "filter") {
      event.preventDefault()
      clearTimeout(deferTimeoutId)
      var form = event.target.closest("form")
      form.dataset.openSingle = "true"
      form.querySelector("input[type='submit']").click()
    }
  })

  var deferTimeoutId
  function defer(fn) {
    return function() {
      var args = arguments
      clearTimeout(deferTimeoutId)
      deferTimeoutId = setTimeout(function() { fn.apply(this, args) }, 500)
    }
  }
}
