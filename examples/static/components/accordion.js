function accordion_toggle(header, e) {
  const accordion = header.parentElement;
  const content = header.nextElementSibling;

  // Toggle open state
  const isOpen = accordion.classList.contains("open");
  accordion.classList.toggle("open", !isOpen);

  // Optional: Close other accordions in group
  const group = accordion.closest(".accordion-group");
  if (group && !isOpen) {
    group.querySelectorAll(".accordion.open").forEach((acc) => {
      if (acc !== accordion) acc.classList.remove("open");
    });
  }
}
