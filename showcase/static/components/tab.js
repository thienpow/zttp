function tab_select(tab, e) {
  const tabGroup = tab.closest(".tab-group");
  const tabId = tab.dataset.tab;
  const content = tabGroup.querySelector(`.tab-content[data-tab="${tabId}"]`);

  // Deactivate all tabs and contents
  tabGroup
    .querySelectorAll(".tab-item")
    .forEach((t) => t.classList.remove("active"));
  tabGroup
    .querySelectorAll(".tab-content")
    .forEach((c) => c.classList.remove("active"));

  // Activate clicked tab and content
  tab.classList.add("active");
  content.classList.add("active");
}
