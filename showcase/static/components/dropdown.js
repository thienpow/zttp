function dropdown_toggle(toggle, e) {
  const dropdown = toggle.nextElementSibling;
  if (!dropdown || !dropdown.classList.contains("dropdown-menu")) return;

  // Toggle visibility
  const isOpen = dropdown.classList.contains("open");
  dropdown.classList.toggle("open", !isOpen);

  // Close on outside click
  if (!isOpen) {
    const closeOnOutside = (e) => {
      if (!toggle.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.remove("open");
        document.removeEventListener("click", closeOnOutside);
      }
    };
    document.addEventListener("click", closeOnOutside);
  }
}
