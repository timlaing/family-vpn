const rows = document.getElementById("wifi-rows");
const addButton = document.getElementById("add-wifi");
rows.addEventListener("click", (event) => {
  const button = event.target.closest(".remove-wifi");
  if (!button) return;
  button.closest(".wifi-row").remove();
  addButton.focus();
});
addButton.addEventListener("click", () => {
  const row = document.createElement("div");
  row.className = "wifi-row";
  const label = document.createElement("label");
  label.append("Wi-Fi network");
  const input = document.createElement("input");
  input.name = "trusted_ssid";
  input.maxLength = 32;
  input.placeholder = "Network name";
  label.append(input);
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary remove-wifi";
  button.textContent = "Delete";
  button.setAttribute("aria-label", "Delete Wi-Fi network");
  row.append(label, button);
  rows.append(row);
  input.focus();
});
