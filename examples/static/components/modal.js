function modal_trigger(trigger, e) {
  const modalId = trigger.dataset.modal;
  const modal = document.getElementById(modalId);
  if (!modal) return;

  // Open modal
  modal.classList.add("open");

  // Close on overlay click
  modal.addEventListener("click", (e) => {
    if (e.target === modal) {
      modal.classList.remove("open");
    }
  });

  // Close on Escape key
  document.addEventListener("keydown", function closeOnEsc(e) {
    if (e.key === "Escape" && modal.classList.contains("open")) {
      modal.classList.remove("open");
      document.removeEventListener("keydown", closeOnEsc);
    }
  });
}
