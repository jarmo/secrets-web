function AutoSuggest() {
  var search = defer(function(event) {
    var target = event.target
    if (target.id === "filter") {
      target.closest("form").querySelector("input[type='submit']").click()
    }
  })

  document.addEventListener('input', search)

  var deferTimeoutId
  function defer(fn) {
    return function() {
      var args = arguments
      clearTimeout(deferTimeoutId)
      deferTimeoutId = setTimeout(function() { fn.apply(this, args) }, 500)
    }
  }
}
