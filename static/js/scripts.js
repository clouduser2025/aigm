function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const totp = document.getElementById('totp').value;

    fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, totp })
    })
        .then(response => response.json())
        .then(data => {
            const resp = document.getElementById('login-response');
            if (data.success) {
                resp.textContent = 'Login successful!';
            } else {
                resp.textContent = 'Login failed!';
            }
        });
}

function placeOrder() {
    const symbol = document.getElementById('order-symbol').value;
    const price = document.getElementById('order-price').value;
    const quantity = document.getElementById('order-quantity').value;

    fetch('/api/place_order', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orderParams: { symbol, price, quantity } })
    })
        .then(response => response.json())
        .then(data => {
            const resp = document.getElementById('order-response');
            resp.textContent = data.success ? 'Order placed!' : 'Order failed!';
        });
}

function createGTT() {
    const symbol = document.getElementById('gtt-symbol').value;
    const price = document.getElementById('gtt-price').value;

    fetch('/api/create_gtt_rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gttParams: { symbol, price } })
    })
        .then(response => response.json())
        .then(data => {
            const resp = document.getElementById('gtt-create-response');
            resp.textContent = data.success ? 'GTT rule created!' : 'Failed to create GTT rule!';
        });
}

function listGTT() {
    fetch('/api/list_gtt_rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            const resp = document.getElementById('gtt-list-response');
            resp.textContent = data.success ? JSON.stringify(data.gtt_list, null, 2) : 'Failed to fetch GTT rules!';
        });
}
