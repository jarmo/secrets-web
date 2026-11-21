document.addEventListener("toggle", function(event) {
  var panel = event.target
  if (!panel.matches || !panel.matches("#add-secret, #secrets details.secret") || !panel.open) return

  document.querySelectorAll("#add-secret[open], #secrets details.secret[open]").forEach(function(other) {
    if (other !== panel) other.open = false
  })

  var firstField = panel.querySelector('input[name="name"]')
  if (firstField) firstField.focus({preventScroll: true})
}, true)

function resetDeleteConfirmation(secret) {
  var confirmation = secret.querySelector(".delete-confirm-body")
  var toggle = secret.querySelector("[data-delete-toggle]")
  if (!confirmation || !toggle) return
  confirmation.hidden = true
  toggle.setAttribute("aria-expanded", "false")
  var input = confirmation.querySelector("[data-delete-name]")
  if (input) input.value = ""
  var submit = confirmation.querySelector('button[type="submit"]')
  if (submit) submit.disabled = true
}

document.addEventListener("toggle", function(event) {
  if (event.target.matches && event.target.matches("#secrets details.secret") && !event.target.open) {
    resetDeleteConfirmation(event.target)
  }
}, true)

document.addEventListener("click", function(event) {
  var toggle = event.target.closest("[data-delete-toggle]")
  if (!toggle) return
  var secret = toggle.closest("details.secret")
  var confirmation = secret.querySelector(".delete-confirm-body")
  if (!confirmation.hidden) {
    resetDeleteConfirmation(secret)
    toggle.focus({preventScroll: true})
    return
  }
  confirmation.hidden = false
  toggle.setAttribute("aria-expanded", "true")
  var input = confirmation.querySelector("[data-delete-name]")
  if (input) input.focus({preventScroll: true})
})

document.addEventListener("input", function(event) {
  if (!event.target.matches || !event.target.matches("[data-delete-name]")) return
  var form = event.target.closest("form")
  form.querySelector('button[type="submit"]').disabled = event.target.value !== event.target.dataset.deleteName
})

document.addEventListener("click", function(event) {
  if (!event.target.closest("[data-delete-cancel]")) return
  var secret = event.target.closest("details.secret")
  resetDeleteConfirmation(secret)
  secret.querySelector("[data-delete-toggle]").focus({preventScroll: true})
})

document.addEventListener("submit", function(event) {
  if (!event.target.matches || !event.target.matches("form.delete")) return
  var input = event.target.querySelector("[data-delete-name]")
  if (!input || input.value !== input.dataset.deleteName) event.preventDefault()
}, true)

window.addEventListener("keydown", function(event) {
  if (event.key !== "Escape" || event.target.matches(".filter-input")) return
  var panel = event.target.closest("#add-secret[open], #secrets details.secret[open]") ||
    document.querySelector("#add-secret[open], #secrets details.secret[open]")
  if (!panel) return
  event.preventDefault()
  event.stopImmediatePropagation()
  panel.open = false
  if (panel.matches("#secrets details.secret")) resetDeleteConfirmation(panel)
  panel.querySelector("summary").focus({preventScroll: true})
}, true)
