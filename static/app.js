const inspectForm = document.querySelector("#inspect-form");
const ipInput = document.querySelector("#ip-input");
const formError = document.querySelector("#form-error");
const resultsBody = document.querySelector("#results-body");
const rulesBody = document.querySelector("#rules-body");
const ruleForm = document.querySelector("#rule-form");

function renderResults(data) {
  document.querySelector("#result-ip").textContent = data.ip;
  document.querySelector("#allowed-count").textContent = data.summary.allowed;
  document.querySelector("#denied-count").textContent = data.summary.denied;
  resultsBody.replaceChildren(...data.results.map((result) => {
    const row = document.createElement("tr");
    const serviceCell = row.insertCell();
    const serviceMark = document.createElement("span");
    serviceMark.className = "service-mark";
    serviceMark.textContent = result.name.slice(0, 1);
    serviceCell.append(serviceMark, document.createTextNode(result.name));

    const portCell = row.insertCell();
    const port = document.createElement("code");
    port.textContent = result.port;
    portCell.append(port);

    const protocolCell = row.insertCell();
    const protocol = document.createElement("span");
    protocol.className = "protocol-tag";
    protocol.textContent = result.protocol;
    protocolCell.append(protocol);

    const permissionCell = row.insertCell();
    const permission = document.createElement("span");
    permission.className = `permission ${result.action.toLowerCase()}`;
    const permissionDot = document.createElement("i");
    permission.append(permissionDot, document.createTextNode(result.action));
    permissionCell.append(permission);

    const sourceCell = row.insertCell();
    sourceCell.className = "decision-source";
    sourceCell.append(document.createTextNode(result.reason));
    if (result.source) {
      const source = document.createElement("code");
      source.textContent = result.source;
      sourceCell.append(document.createTextNode(" "), source);
    }
    return row;
  }));
}

async function evaluateAddress(address) {
  formError.hidden = true;
  const response = await fetch("/api/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip: address }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Could not evaluate this address.");
  renderResults(data);
}

inspectForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = inspectForm.querySelector("button[type='submit']");
  button.disabled = true;
  button.querySelector("span:first-child").textContent = "Evaluating…";
  try {
    await evaluateAddress(ipInput.value.trim());
  } catch (error) {
    formError.textContent = error.message;
    formError.hidden = false;
  } finally {
    button.disabled = false;
    button.querySelector("span:first-child").textContent = "Evaluate address";
  }
});

document.querySelector(".notice-close").addEventListener("click", (event) => event.currentTarget.closest(".notice").remove());
document.querySelector("#open-rule-form").addEventListener("click", () => {
  ruleForm.hidden = false;
  ruleForm.querySelector("input").focus();
});
document.querySelector("#close-rule-form").addEventListener("click", () => { ruleForm.hidden = true; });

ruleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorElement = document.querySelector("#rule-error");
  errorElement.hidden = true;
  const payload = Object.fromEntries(new FormData(ruleForm).entries());
  try {
    const response = await fetch("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not save this rule.");
    window.location.reload();
  } catch (error) {
    errorElement.textContent = error.message;
    errorElement.hidden = false;
  }
});

rulesBody.addEventListener("click", async (event) => {
  const button = event.target.closest(".delete-rule");
  if (!button) return;
  const row = button.closest("tr");
  try {
    const response = await fetch(`/api/rules/${encodeURIComponent(row.dataset.ruleId)}`, { method: "DELETE" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not delete this rule.");
    const action = row.querySelector(".permission").classList.contains("allow") ? "allow" : "deny";
    row.remove();
    document.querySelectorAll("#rules-body tr").forEach((item, index) => {
      item.querySelector(".priority-tag").textContent = String(index + 1).padStart(2, "0");
    });
    const ruleCount = Number(document.querySelector("#rule-count").textContent) - 1;
    document.querySelector("#rule-count").textContent = ruleCount;
    document.querySelector("#rule-count-chip").textContent = ruleCount;
    document.querySelector("#nav-rule-count").textContent = ruleCount;
    const actionCount = document.querySelector(`#${action}-rule-count`);
    actionCount.textContent = Number(actionCount.textContent) - 1;
    await evaluateAddress(ipInput.value.trim());
  } catch (error) {
    window.alert(error.message);
  }
});

evaluateAddress(ipInput.value).catch((error) => {
  formError.textContent = error.message;
  formError.hidden = false;
});