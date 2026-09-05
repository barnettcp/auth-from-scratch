// Renders the "live process trace" panel: a small ordered log of what just
// happened, passed from the server as a JSON blob in the container's
// data-trace attribute. Purely presentational -- this script has no bearing
// on the security of the flow, which is entirely decided server-side.

document.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("trace-container");
  if (!container) return;

  let entries = [];
  try {
    entries = JSON.parse(container.getAttribute("data-trace") || "[]");
  } catch (e) {
    entries = [];
  }

  entries.forEach((entry, i) => {
    const line = document.createElement("div");
    line.className = `trace-line actor-${entry.actor}`;
    line.style.animationDelay = `${i * 0.12}s`;

    const icon = document.createElement("span");
    icon.className = "icon";
    icon.textContent = entry.icon || "•";

    const actor = document.createElement("span");
    actor.className = "actor";
    actor.textContent = entry.actor;

    const message = document.createElement("span");
    message.className = "message";
    message.textContent = entry.message;

    line.appendChild(icon);
    line.appendChild(actor);
    line.appendChild(message);
    container.appendChild(line);
  });
});
