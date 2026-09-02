let ws;
const feedList = document.getElementById("feedList");
const resultCard = document.getElementById("resultCard");
const resultTitle = document.getElementById("resultTitle");
const resultDetails = document.getElementById("resultDetails");

// Tab switching logic
function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

  event.currentTarget.classList.add("active");
  document.getElementById(tabId).classList.add("active");
}

// WebSocket Connection
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

  ws = new WebSocket(wsUrl);

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "TELEMETRY_UPDATE") {
        updateStats(msg.data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  ws.onclose = () => {
    setTimeout(connectWebSocket, 2000);
  };
}

function updateStats(data) {
  const metrics = data.metrics || {};
  const traffic = metrics.traffic || {};

  const totalPackets = (traffic.packets_sent || 0) + (traffic.packets_received || 0);
  document.getElementById("statPackets").innerText = totalPackets.toLocaleString();
  document.getElementById("statThreats").innerText = (traffic.threats_neutralized || 0).toLocaleString();

  const totalKb = ((traffic.bytes_sent || 0) + (traffic.bytes_received || 0)) / 1024;
  document.getElementById("statBytes").innerText = totalKb > 1024 ? `${(totalKb/1024).toFixed(2)} MB` : `${totalKb.toFixed(1)} KB`;

  // Render logs
  if (data.recent_events && data.recent_events.length > 0) {
    renderFeed(data.recent_events);
  }
}

function renderFeed(events) {
  feedList.innerHTML = "";
  const reversed = [...events].reverse();
  reversed.forEach(ev => {
    const item = document.createElement("div");
    item.className = `feed-item ${ev.severity}`;
    item.innerHTML = `
      <div>
        <strong>[${ev.category}]</strong> ${ev.title}
        <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 2px;">${JSON.stringify(ev.details)}</div>
      </div>
      <div class="feed-time">${ev.time_str}</div>
    `;
    feedList.appendChild(item);
  });
}

function showResult(title, details, isSuccess = true) {
  resultCard.style.display = "block";
  resultCard.className = `result-card ${isSuccess ? 'success' : 'blocked'}`;
  resultTitle.innerHTML = isSuccess ? `✅ ${title}` : `❌ ${title}`;
  resultDetails.innerHTML = details;
}

// Send user payload
async function sendCustomPayload() {
  const input = document.getElementById("payloadInput");
  const text = input.value.trim();
  if (!text) return;

  try {
    const resp = await fetch("/api/simulate-threat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ threat_type: "CUSTOM", custom_message: text })
    });
    const data = await resp.json();
    const res = data.result || {};

    if (res.accepted) {
      showResult(
        "Information Cleared & Delivered",
        `<b>Status:</b> Encrypted with AES-256-GCM and verified tamper-free.<br>
         <b>Custody Chain Length:</b> ${res.chain_info?.chain_length} | <b>Head:</b> <code>${res.chain_info?.chain_head_hex}</code><br>
         <b>Static Risk Score:</b> ${res.static_telemetry?.risk_score}/100 (${res.static_telemetry?.risk_level})`,
        true
      );
      input.value = "";
    } else {
      let extraInfo = "";
      if (res.static_telemetry) {
        if (res.static_telemetry.detected_apis?.length) {
          extraInfo += `<br><b>Suspicious APIs Flagged:</b> <code>${res.static_telemetry.detected_apis.join(", ")}</code>`;
        }
        if (res.static_telemetry.detected_ips?.length) {
          extraInfo += `<br><b>Flagged IPs:</b> <code>${res.static_telemetry.detected_ips.join(", ")}</code>`;
        }
        if (res.static_telemetry.detected_urls?.length) {
          extraInfo += `<br><b>Flagged URLs:</b> <code>${res.static_telemetry.detected_urls.join(", ")}</code>`;
        }
      }
      if (res.quarantine_path) {
        extraInfo += `<br><b>Quarantine Location:</b> <code>${res.quarantine_path}</code>`;
      }
      showResult(
        "Threat / Risky Payload Blocked by Harness",
        `<b>Reason:</b> ${res.reason}${extraInfo}`,
        false
      );
    }
  } catch (e) {
    showResult("Transmission Error", e.message, false);
  }
}

// Security test buttons
async function runTest(type) {
  switchTab('tab-send'); // Bring user back to see the instant result
  try {
    const resp = await fetch("/api/simulate-threat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ threat_type: type })
    });
    const data = await resp.json();
    const res = data.result || {};

    if (res.accepted) {
      showResult(
        "Test Payload Cleared",
        `Packet passed all filters. Hash chain length: ${res.chain_info?.chain_length}`,
        true
      );
    } else {
      showResult(
        "Threat Neutralized & Blocked",
        `<b>Defense Mechanism Triggered:</b> ${res.reason}<br>
         ${res.threat ? `<b>Detected:</b> ${res.threat.detections[0]?.name} (${res.threat.severity})<br>` : ''}
         ${res.quarantine_path ? `<b>Quarantine Location:</b> <code>${res.quarantine_path}</code>` : ''}`,
        false
      );
    }
  } catch (e) {
    showResult("Test Error", e.message, false);
  }
}

// Audit integrity
async function checkIntegrity() {
  switchTab('tab-send');
  try {
    const resp = await fetch("/api/integrity");
    const data = await resp.json();
    if (data.integrity_ok) {
      showResult(
        "Codebase Integrity Verified",
        "All Python files and virus signatures match pristine SHA-256 baseline hashes. Zero unauthorized tampering detected on disk.",
        true
      );
    } else {
      showResult(
        "Tampering Detected on Disk!",
        `Modified files: ${JSON.stringify(data.tampered_files)}`,
        false
      );
    }
  } catch (e) {
    showResult("Audit Error", e.message, false);
  }
}

// -------------------------------------------------------------
// WhatsApp & Email Armor Bridge Handlers
// -------------------------------------------------------------
async function lockForWhatsApp() {
  const plainText = document.getElementById("whatsappPlainText").value.trim();
  if (!plainText) return;

  try {
    const resp = await fetch("/api/armor/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: plainText })
    });
    const data = await resp.json();
    if (data.status === "SUCCESS") {
      document.getElementById("whatsappArmoredOutput").value = data.armored_text;
      document.getElementById("whatsappLockResult").style.display = "block";
    }
  } catch (e) {
    alert("Error locking message: " + e.message);
  }
}

function copyWhatsAppArmor() {
  const output = document.getElementById("whatsappArmoredOutput");
  output.select();
  navigator.clipboard.writeText(output.value);
  alert("📋 Copied Armored Message to Clipboard! Now switch to WhatsApp Web and press Ctrl+V to send it.");
}

async function unlockFromWhatsApp() {
  const armoredInput = document.getElementById("whatsappArmoredInput").value.trim();
  if (!armoredInput) return;

  try {
    const resp = await fetch("/api/armor/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ armored_text: armoredInput })
    });
    const data = await resp.json();
    
    const resultDiv = document.getElementById("whatsappUnlockResult");
    const card = document.getElementById("whatsappUnlockCard");
    const title = document.getElementById("whatsappUnlockTitle");
    const details = document.getElementById("whatsappUnlockDetails");

    resultDiv.style.display = "block";

    if (data.accepted) {
      card.className = "result-card success";
      title.innerHTML = "✅ Message Verified & Decrypted";
      details.innerHTML = `
        <div style="background: rgba(0,0,0,0.4); padding: 0.75rem; border-radius: 6px; color: #fff; font-size: 0.95rem; margin-bottom: 0.5rem; font-family: var(--font);">
          "${data.plaintext}"
        </div>
        <span style="font-size: 0.75rem; color: var(--text-dim);">
          ● Ed25519 Sender Signature: <b>VERIFIED VALID</b><br>
          ● AES-256-GCM Integrity: <b>UNALTERED</b><br>
          ● Antivirus & Exploit Scan: <b>CLEAN (Zero Malware)</b>
        </span>
      `;
    } else {
      card.className = "result-card blocked";
      title.innerHTML = "❌ Message Rejected / Tampered";
      details.innerHTML = `<b>Block Reason:</b> ${data.reason}`;
    }
  } catch (e) {
    alert("Error unlocking message: " + e.message);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  connectWebSocket();
});

