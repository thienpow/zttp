function button_click(button, e) {
  // Skip if button is disabled
  if (button.disabled) return;

  // Get button position and dimensions
  const rect = button.getBoundingClientRect();
  const x = e.clientX - rect.left;
  const y = e.clientY - rect.top;

  // Create ripple element
  const ripple = document.createElement("span");
  ripple.className = "ripple";
  ripple.style.left = `${x}px`;
  ripple.style.top = `${y}px`;

  // Append and remove after animation
  button.appendChild(ripple);
  setTimeout(() => ripple.remove(), 600);
}
