function AutoSuggest() {
  var search = defer(function(event) {
    var target = event.target
    if (target.id === "filter") {
      var form = target.closest("form")
      form.querySelector("input[type='submit']").click()
    }
  })

  function syncClearButton(input) {
    var clear = input.closest(".filter").querySelector("[data-clear-filter]")
    if (clear) clear.hidden = !input.value
  }

  document.addEventListener('click', function(event) {
    var clear = event.target.closest("[data-clear-filter]")
    if (!clear) return
    var input = clear.closest(".filter").querySelector(".filter-input")
    input.value = ""
    input.dispatchEvent(new Event("input", {bubbles: true}))
    input.focus()
  })

  document.querySelectorAll(".filter-input").forEach(syncClearButton)

  document.addEventListener('input', function(event) {
    if (event.target.classList && event.target.classList.contains("filter-input")) syncClearButton(event.target)
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
