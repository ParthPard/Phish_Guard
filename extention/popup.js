document.addEventListener('DOMContentLoaded', function() {
    // 1. Get the URL of the current active tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        let currentUrl = tabs[0].url;
        document.getElementById('url-display').textContent = currentUrl;

        // 2. Send that URL to your running FastAPI backend
        fetch('http://localhost:8000/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        })
        .then(response => response.json())
        .then(data => {
            // 3. Update the popup UI based on the ML prediction
            let resultDiv = document.getElementById('result');
            if(data.is_malicious) {
                resultDiv.textContent = "⚠️ MALICIOUS SITE";
                resultDiv.className = "danger";
            } else {
                resultDiv.textContent = "✅ SAFE SITE";
                resultDiv.className = "safe";
            }
        })
        .catch(error => {
            document.getElementById('result').textContent = "Backend Offline. Start Uvicorn!";
        });
    });
});