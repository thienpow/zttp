// Map of components to their selectors, handler functions, and event types
const componentHandlers = [
  { selector: ".btn", handler: "button_click", event: "click" },
  {
    selector: ".tooltip-trigger",
    handler: "tooltip_trigger",
    event: "mouseover",
  },
  {
    selector: ".tooltip-trigger",
    handler: "tooltip_trigger",
    event: "mouseout",
  },
  { selector: ".dropdown-toggle", handler: "dropdown_toggle", event: "click" },
  { selector: ".modal-trigger", handler: "modal_trigger", event: "click" },
  { selector: ".tab-item", handler: "tab_select", event: "click" },
  {
    selector: ".accordion-header",
    handler: "accordion_toggle",
    event: "click",
  },
  { selector: ".modal", handler: "modal_trigger", event: "keydown" }, // For Escape key
];

// Set up event listeners for each event type
const eventTypes = [...new Set(componentHandlers.map((h) => h.event))];
eventTypes.forEach((eventType) => {
  document.addEventListener(eventType, (e) => {
    componentHandlers
      .filter((h) => h.event === eventType)
      .forEach((h) => {
        const element = e.target.closest(h.selector);
        if (element && typeof window[h.handler] === "function") {
          window[h.handler](element, e);
        }
      });
  });
});
