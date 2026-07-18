const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const statusPill = document.getElementById("status-pill");
const requestMessage = document.getElementById("request-message");
const predictionValue = document.getElementById("prediction-value");
const threatValue = document.getElementById("threat-value");
const urlValue = document.getElementById("url-value");
const explanationList = document.getElementById("explanation-list");
const featureList = document.getElementById("feature-list");
const chartLegend = document.getElementById("chart-legend");
const chartContext = document.getElementById("feature-chart");

const defaultColors = ["#4ca6ff", "#7bc5ff", "#9ad8ff", "#74b0ff", "#5a91f0"];
const dangerColors = ["#ff4d4d", "#ff6666", "#ff8080", "#e63939", "#cc0000"];
const warningColors = ["#ffa64d", "#ffb366", "#ffc080", "#ff9933", "#ff8c1a"];
const safeColors = ["#47d147", "#5cd65c", "#70db70", "#33cc33", "#29a329"];

let featureChart = null;

function setStatus(label, mode) {
  statusPill.textContent = label;
  statusPill.className = `status-pill ${mode}`;
}

function truncateText(value, maxLength = 64) {
  if (!value) {
    return "No URL yet";
  }

  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

function classifyFeatureValue(value) {
  if (value === 1) {
    return "high-risk";
  }

  if (value === 0) {
    return "medium-risk";
  }

  return "low-risk";
}

function renderExplanation(explanations) {
  if (!explanations.length) {
    explanationList.innerHTML = `
      <article class="empty-card">
        <h3>No explanation entries</h3>
        <p>The backend returned no explainability records for this scan.</p>
      </article>
    `;
    return;
  }

  explanationList.innerHTML = explanations
    .map(
      (item, index) => `
        <article class="explanation-card">
          <h3>${index + 1}. ${item.feature}</h3>
          <p>${item.reason}</p>
          <span class="impact-score">Impact Score: ${Math.abs(item.impact_score).toFixed(4)}</span>
        </article>
      `
    )
    .join("");
}

function renderFeatures(features) {
  const entries = Object.entries(features || {});

  if (!entries.length) {
    featureList.innerHTML = '<p class="empty-state">No extracted features to display yet.</p>';
    return;
  }

  const sortedEntries = entries
    .sort((left, right) => right[1] - left[1])
    .slice(0, 8);

  featureList.innerHTML = sortedEntries
    .map(
      ([feature, value]) => `
        <article class="feature-card">
          <div>
            <strong>${feature}</strong>
            <p>Extracted indicator from the threat detection pipeline.</p>
          </div>
          <span class="feature-value ${classifyFeatureValue(value)}">${value}</span>
        </article>
      `
    )
    .join("");
}

function renderChart(explanations, prediction) {
  let activeColors = defaultColors;
  if (prediction === "Phishing") {
    activeColors = dangerColors;
  } else if (prediction === "Medium Legitimate") {
    activeColors = warningColors;
  } else if (prediction === "Legitimate") {
    activeColors = safeColors;
  }

  const items = explanations.map((item, index) => ({
    label: item.feature,
    score: Math.abs(item.impact_score),
    color: activeColors[index % activeColors.length]
  }));

  if (featureChart) {
    featureChart.destroy();
  }

  if (!items.length) {
    chartLegend.innerHTML = '<p class="empty-state">Run a scan to populate the main feature breakdown.</p>';
    return;
  }

  featureChart = new Chart(chartContext, {
    type: "pie",
    data: {
      labels: items.map((item) => item.label),
      datasets: [
        {
          data: items.map((item) => item.score),
          backgroundColor: items.map((item) => item.color),
          borderColor: "#ffffff",
          borderWidth: 3,
          hoverOffset: 8
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          callbacks: {
            label(context) {
              return `${context.label}: ${Number(context.raw).toFixed(4)}`;
            }
          }
        }
      }
    }
  });

  chartLegend.innerHTML = items
    .map(
      (item) => `
        <div class="legend-row">
          <div class="legend-label">
            <span class="legend-dot" style="background:${item.color}"></span>
            <span class="legend-text">${item.label}</span>
          </div>
          <span class="legend-score">${item.score.toFixed(4)}</span>
        </div>
      `
    )
    .join("");
}

function renderResult(data) {
  predictionValue.textContent = data.prediction || "Unknown";
  
  const threatNum = Number(data.threat_level || 0);
  threatValue.textContent = `${threatNum.toFixed(2)}%`;
  
  const circle = document.getElementById("threat-circle");
  if (circle) {
    // If we want a nice visual effect for threat level, it could go from safe (low) to danger (high), but for now we keep the same styling.
    circle.style.background = `conic-gradient(var(--primary) ${threatNum}%, var(--impact-bg) ${threatNum}%)`;
  }

  urlValue.textContent = truncateText(data.url, 120);
  renderExplanation(data.explanation || []);
  renderFeatures(data.features || {});
  renderChart(data.explanation || [], data.prediction);

  if (data.prediction === "Phishing") {
    document.documentElement.setAttribute('data-theme', 'danger');
    setStatus("Threat detected", "danger");
    requestMessage.textContent = "The model marked this URL as suspicious. Review the explanation and chart carefully.";
  } else if (data.prediction === "Medium Legitimate") {
    document.documentElement.setAttribute('data-theme', 'warning');
    setStatus("Medium threat found but you can browse", "warning");
    requestMessage.textContent = "The model marked this URL as a medium threat. Proceed with caution.";
  } else {
    document.documentElement.setAttribute('data-theme', 'safe');
    setStatus("Looks legitimate", "safe");
    requestMessage.textContent = "The model marked this URL as likely legitimate based on the extracted indicators.";
  }
}

async function scanUrl(url) {
  const response = await fetch("/predict", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });

  const payload = await response.json();

  if (!response.ok) {
    throw new Error(payload.error || "The phishing scan failed.");
  }

  return payload;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = urlInput.value.trim();

  if (!url) {
    setStatus("URL required", "error");
    requestMessage.textContent = "Enter a website URL before starting the scan.";
    return;
  }

  document.documentElement.removeAttribute('data-theme');
  scanButton.disabled = true;
  setStatus("Scanning...", "loading");
  requestMessage.textContent = "Contacting the Flask API and extracting phishing indicators.";
  
  const circle = document.getElementById("threat-circle");
  if (circle) {
    circle.style.background = `conic-gradient(var(--primary) 0%, var(--impact-bg) 0%)`;
  }

  try {
    const result = await scanUrl(url);
    renderResult(result);
  } catch (error) {
    setStatus("Scan failed", "error");
    requestMessage.textContent = error.message;
  } finally {
    scanButton.disabled = false;
  }
});

const qrUploadButton = document.getElementById("qr-upload-button");
const qrUploadInput = document.getElementById("qr-upload");
let html5QrCode = null;

if (qrUploadButton && qrUploadInput) {
  qrUploadButton.addEventListener("click", () => {
    qrUploadInput.click();
  });

  qrUploadInput.addEventListener("change", (e) => {
    if (e.target.files.length === 0) {
      return;
    }
    
    const file = e.target.files[0];
    if (!html5QrCode) {
      html5QrCode = new Html5Qrcode("qr-reader");
    }
    
    html5QrCode.scanFile(file, true)
      .then(decodedText => {
        urlInput.value = decodedText;
        scanButton.click();
      })
      .catch(err => {
        setStatus("QR Scan failed", "error");
        requestMessage.textContent = "Could not find a valid QR code in the uploaded image.";
      });
      
    // Reset input so the same file can be selected again if needed
    qrUploadInput.value = "";
  });
}

