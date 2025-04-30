function tooltip_trigger(trigger, e) {
  if (e.type === "mouseover") {
    // Create tooltip element if not exists
    let tooltip = trigger.querySelector(".tooltip");
    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.className = "tooltip";
      tooltip.textContent = trigger.dataset.tooltip || "Tooltip";
      trigger.appendChild(tooltip);
    }
    // Position tooltip (basic, above element)
    const rect = trigger.getBoundingClientRect();
    tooltip.style.top = `${-tooltip.offsetHeight - 5}px`;
    tooltip.style.left = `${rect.width / 2 - tooltip.offsetWidth / 2}px`;
    tooltip.classList.add("visible");
  } else if (e.type === "mouseout") {
    // Hide tooltip
    const tooltip = trigger.querySelector(".tooltip");
    if (tooltip) {
      tooltip.classList.remove("visible");
    }
  }
}

// Add mouseout listener via global.js
componentHandlers.push({
  selector: ".tooltip-trigger",
  handler: "tooltip_trigger",
  event: "mouseout",
});
