"use strict";
const mode = document.getElementById("mode");
const fields = document.getElementById("radius-fields");
function updateAuthentication() {
  const radius = mode.value === "radius";
  fields.hidden = !radius;
  for (const input of fields.querySelectorAll("input")) {
    input.disabled = !radius;
    input.required = radius && ["server", "auth_port", "acct_port", "nas_identifier"].includes(input.name);
  }
}
mode.addEventListener("change", updateAuthentication);
updateAuthentication();
