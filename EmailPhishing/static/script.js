document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyze-btn');
    const emailFileInput = document.getElementById('email-file');
    const resultSection = document.getElementById('result-section');
    const resultContent = document.getElementById('result-content');
    const loader = document.querySelector('.loader');
    const btnText = document.querySelector('.btn-text');

    analyzeBtn.addEventListener('click', async () => {
        const file = emailFileInput.files[0];
        if (!file) {
            alert('Please upload a PDF file before scanning.');
            return;
        }

        // Set UI to loading state
        analyzeBtn.disabled = true;
        btnText.textContent = 'Analyzing...';
        loader.classList.remove('hidden');
        resultSection.classList.add('hidden');
        resultContent.innerHTML = '';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to analyze email. Please try again.');
            }

            // Convert Markdown to HTML
            if (typeof marked !== 'undefined') {
                resultContent.innerHTML = marked.parse(data.result);
            } else {
                resultContent.textContent = data.result;
            }

            // Extract probability and render circular graph
            const verdictElement = resultContent.querySelector('.verdict');
            if (verdictElement) {
                const probabilityAttr = verdictElement.getAttribute('data-probability');
                if (probabilityAttr) {
                    const probability = parseInt(probabilityAttr, 10);
                    if (!isNaN(probability)) {
                        renderCircularGraph(probability, resultContent);
                    }
                }
            }
            
            resultSection.classList.remove('hidden');
        } catch (error) {
            resultContent.innerHTML = `<div class="error-text"><strong>Error:</strong> ${error.message}</div>`;
            resultSection.classList.remove('hidden');
        } finally {
            // Restore UI state
            analyzeBtn.disabled = false;
            btnText.textContent = 'Scan for Phishing';
            loader.classList.add('hidden');
        }
    });
});

function renderCircularGraph(probability, container) {
    let riskClass = 'low-risk';
    let riskText = 'Low Risk';
    if (probability >= 70) {
        riskClass = 'high-risk';
        riskText = 'High Risk';
    } else if (probability >= 30) {
        riskClass = 'medium-risk';
        riskText = 'Medium Risk';
    }

    const graphHTML = `
        <div class="risk-graph-container">
            <svg viewBox="0 0 36 36" class="circular-chart ${riskClass}">
                <path class="circle-bg"
                    d="M18 2.0845
                    a 15.9155 15.9155 0 0 1 0 31.831
                    a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path class="circle"
                    stroke-dasharray="${probability}, 100"
                    d="M18 2.0845
                    a 15.9155 15.9155 0 0 1 0 31.831
                    a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <text x="18" y="20.35" class="percentage">${probability}%</text>
            </svg>
            <div class="risk-label ${riskClass}">${riskText}</div>
        </div>
    `;

    const verdictEl = container.querySelector('.verdict');
    if (verdictEl) {
        verdictEl.insertAdjacentHTML('afterend', graphHTML);
    } else {
        container.insertAdjacentHTML('afterbegin', graphHTML);
    }
}
