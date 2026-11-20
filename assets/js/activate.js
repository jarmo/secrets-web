document.addEventListener("DOMContentLoaded", function() {
  var form = document.getElementById("activate")
  if (!form) return

  form.addEventListener("submit", function(event) {
    event.preventDefault()
    fetch(form.action, {
      method: "POST",
      body: new FormData(form),
      headers: {"X-Csrf-Token": document.querySelector('meta[name="x-csrf-token"]').content}
    }).then(function(response) {
      return response.text()
    }).then(function(html) {
      document.open()
      document.write(html)
      document.close()
    }).catch(function() {
      alert("Unable to activate account. Please try again.")
    })
  })
})
