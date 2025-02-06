    <!-- Full-Width Real-Time Stock Chart -->
    <div class="row mt-4">
        <div class="col-md-12">
            <div class="card shadow-lg rounded border-0" style="background: #121212; color: white; width: 100%;">
                <div class="card-body text-center">
                    <h5 class="card-title text-warning"><i class="fas fa-chart-line"></i> Real-Time Stock Chart</h5>
                    <div class="d-flex justify-content-center align-items-center mb-3">
                        <label for="stockSymbol" class="me-2 fw-bold">Stock Symbol:</label>
                        <input type="text" id="stockSymbol" class="form-control w-25 text-dark" value="NSE:INFY">
                        <button class="btn btn-primary ms-2 shadow-lg" onclick="updateChart()">Update Chart</button>
                    </div>
                    <div id="chartContainer" style="height: 750px;"></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- TradingView Integration -->
<script src="https://s3.tradingview.com/tv.js"></script>
<script>
function updateChart() {
    let symbol = document.getElementById("stockSymbol").value;
    document.getElementById("chartContainer").innerHTML = "";
    new TradingView.widget({
        "container_id": "chartContainer",
        "autosize": true,
        "symbol": symbol,
        "interval": "5",
        "timezone": "Etc/UTC",
        "theme": "dark",
        "style": "1",
        "locale": "en",
        "toolbar_bg": "#121212",
        "hide_side_toolbar": false,
        "allow_symbol_change": true,
        "studies": ["MACD@tv-basicstudies", "RSI@tv-basicstudies"]
    });
}
</script>