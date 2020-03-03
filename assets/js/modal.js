function Modal() {
  document.addEventListener('click', showModal)
  document.addEventListener('click', closeOnClick)
  document.addEventListener('click', closeOnClickOutside)
  document.addEventListener('keyup', closeOnEscapeKeypress)

  function showModal(event) {
    var target = event.target
    if (target.classList.contains("btn-modal")) {
      event.preventDefault()
      setTimeout(function() {
        var modalContainer = document.querySelector(target.dataset.target)
        show(modalContainer)
        var firstVisibleAutofocusableField = Array
          .from(modalContainer.querySelectorAll("input[autofocus]"))
          .find(input => input.offsetParent)

        if (firstVisibleAutofocusableField) firstVisibleAutofocusableField.focus()
      }, 0)
    }
  }

  function closeOnClick(event) {
    var target = event.target
    if (target.classList.contains("close")) {
      event.preventDefault()
      close(shownModal())
    }
  }

  function closeOnClickOutside(event) {
    if (!event.target.closest(".modal-container")) {
      var modal = shownModal()
      if (modal) close(modal)
    }
  }

  function closeOnEscapeKeypress(event) {
    if (event.keyCode == 27) {
      var modal = shownModal()
      if (modal) close(modal)
    }
  }

  function shownModal() {
    return Array.from(document.querySelectorAll(".modal")).filter(isShown)[0]
  }

  function isShown(modal) {
    return modal.style.display !== "none"
  }

  function show(modal) {
    modal.style.display = "block"
  }

  function close(modal) {
    modal.style.display = "none"
  }
}
