<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Supplier & Logistics Hub | SJM</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        /* --- PROFESSIONAL DARK THEME --- */
        :root {
            --bg-dark: #0f0f0f;
            --panel: #1a1a1a;
            --border: #333;
            --gold: #d4af37;
            --gold-hover: #b5952f;
            --text: #e0e0e0;
            --text-muted: #888;
            --danger: #ff4d4d;
            --success: #00e676;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }
        body { background: var(--bg-dark); color: var(--text); padding: 40px; }

        /* HEADER & STOCK DASHBOARD (Task 1.3.1) */
        .header { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 30px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }
        .header h1 { font-weight: 300; color: var(--gold); letter-spacing: 1px; }
        
        .stock-ticker { display: flex; gap: 20px; }
        .ticker-item { background: var(--panel); padding: 10px 20px; border-radius: 6px; border: 1px solid var(--border); font-size: 0.9rem; }
        .ticker-item strong { color: var(--gold); font-size: 1.1rem; margin-right: 5px; }

        /* TABS */
        .tabs { display: flex; gap: 5px; margin-bottom: 20px; }
        .tab-btn { background: var(--panel); border: 1px solid var(--border); color: var(--text-muted); padding: 12px 25px; cursor: pointer; transition: 0.3s; font-weight: 600; }
        .tab-btn.active { background: var(--gold); color: #000; border-color: var(--gold); }
        .tab-content { display: none; animation: fadeIn 0.4s; }
        .tab-content.active { display: block; }

        /* CARDS & FORMS */
        .card { background: var(--panel); padding: 30px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 20px; }
        .card h3 { color: var(--gold); margin-bottom: 20px; font-weight: 400; border-left: 3px solid var(--gold); padding-left: 10px; }

        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .input-group label { display: block; margin-bottom: 8px; color: var(--text-muted); font-size: 0.85rem; }
        input, select { width: 100%; padding: 12px; background: #0a0a0a; border: 1px solid var(--border); color: #fff; border-radius: 4px; outline: none; }
        input:focus, select:focus { border-color: var(--gold); }

        /* BUTTONS */
        .btn { padding: 12px 20px; border: none; border-radius: 4px; font-weight: 600; cursor: pointer; transition: 0.3s; width: 100%; margin-top: 20px; }
        .btn-gold { background: var(--gold); color: #000; }
        .btn-gold:hover { background: var(--gold-hover); }
        .btn-sm { width: auto; padding: 6px 12px; font-size: 0.8rem; margin-top: 0; }
        .btn-danger { background: transparent; border: 1px solid var(--danger); color: var(--danger); }
        .btn-danger:hover { background: var(--danger); color: #fff; }

        /* TABLES (Task 1.1.1 & 1.2.3) */
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { text-align: left; padding: 15px; color: var(--text-muted); font-size: 0.85rem; border-bottom: 1px solid var(--border); }
        td { padding: 15px; border-bottom: 1px solid var(--border); color: #ddd; }
        tr:hover { background: #222; }

        /* UPLOAD (Task 1.2.4) */
        .upload-box { border: 2px dashed var(--border); padding: 20px; text-align: center; cursor: pointer; color: var(--text-muted); transition: 0.3s; }
        .upload-box:hover { border-color: var(--gold); color: var(--gold); }

        /* MODAL (Task 1.1.3) */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); align-items: center; justify-content: center; z-index: 100; }
        .modal-content { background: var(--panel); padding: 30px; width: 400px; border: 1px solid var(--gold); border-radius: 8px; }

        /* TOAST */
        .toast { position: fixed; top: 20px; right: 20px; padding: 15px 25px; border-radius: 4px; color: #fff; display: none; animation: slideIn 0.3s; z-index: 200; }
        .toast.success { background: var(--success); }
        .toast.error { background: var(--danger); }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>Logistics Command</h1>
            <p style="color:var(--text-muted); font-size:0.9rem;">Manage Suppliers & Incoming Inventory</p>
        </div>
        <div class="stock-ticker" id="stockTicker">
            <div class="ticker-item">Loading Stock...</div>
        </div>
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('suppliers')">1. Supplier Management</button>
        <button class="tab-btn" onclick="switchTab('deliveries')">2. Delivery Processing</button>
    </div>

    <div id="suppliers" class="tab-content active">
        <div class="card">
            <h3><i class="fa-solid fa-user-plus"></i> Register New Supplier</h3>
            <form id="addSupplierForm">
                <div class="form-grid">
                    <div class="input-group">
                        <label>Company Name</label>
                        <input type="text" id="supName" required>
                    </div>
                    <div class="input-group">
                        <label>Contact Person</label>
                        <input type="text" id="supContact">
                    </div>
                    <div class="input-group">
                        <label>Email Address</label>
                        <input type="email" id="supEmail" required>
                    </div>
                    <div class="input-group">
                        <label>Phone Number</label>
                        <input type="text" id="supPhone">
                    </div>
                </div>
                <button type="submit" class="btn btn-gold">Save Supplier Record</button>
            </form>
        </div>

        <div class="card">
            <h3><i class="fa-solid fa-list"></i> Supplier Directory</h3>
            <table>
                <thead>
                    <tr><th>Company</th><th>Contact</th><th>Score</th><th>Actions</th></tr>
                </thead>
                <tbody id="supplierTable"></tbody>
            </table>
        </div>
    </div>

    <div id="deliveries" class="tab-content">
        <div class="card">
            <h3><i class="fa-solid fa-truck-ramp-box"></i> Incoming Delivery</h3>
            <form id="deliveryForm">
                <div class="form-grid">
                    <div class="input-group">
                        <label>Supplier (Task 1.2.2)</label>
                        <select id="delSupplier" required><option>Loading...</option></select>
                    </div>
                    <div class="input-group">
                        <label>Jewellery Type</label>
                        <select id="delType" required>
                            <option value="Gold Ring 22k">Gold Ring 22k</option>
                            <option value="Silver Chain">Silver Chain</option>
                            <option value="Platinum Pendant">Platinum Pendant</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Quantity Received</label>
                        <input type="number" id="delQty" min="1" required>
                    </div>
                    <div class="input-group">
                        <label>Digital Invoice (Task 1.2.4)</label>
                        <div class="upload-box" onclick="document.getElementById('delFile').click()">
                            <i class="fa-solid fa-cloud-arrow-up"></i> Upload PDF/IMG
                            <input type="file" id="delFile" hidden>
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn btn-gold">Process Delivery & Update Stock</button>
            </form>
        </div>

        <div class="card">
            <h3><i class="fa-solid fa-clock-rotate-left"></i> Delivery History</h3>
            <table>
                <thead>
                    <tr><th>Date</th><th>Supplier</th><th>Item</th><th>Qty</th><th>Status</th></tr>
                </thead>
                <tbody id="deliveryTable"></tbody>
            </table>
        </div>
    </div>

    <div id="editModal" class="modal">
        <div class="modal-content">
            <h3>Edit Supplier</h3>
            <input type="hidden" id="editId">
            <div class="input-group" style="margin-bottom:15px">
                <label>Company Name</label>
                <input type="text" id="editName">
            </div>
            <div class="input-group" style="margin-bottom:15px">
                <label>Email</label>
                <input type="email" id="editEmail">
            </div>
            <button class="btn btn-gold" onclick="updateSupplier()">Update Record</button>
            <button class="btn btn-danger" style="margin-top:10px" onclick="closeModal()">Cancel</button>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    <script>
        const API_PATH = 'api/logic';

        // --- CORE FUNCTIONS ---
        function switchTab(id) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            event.target.classList.add('active');
        }

        function showToast(msg, type) {
            const t = document.getElementById('toast');
            t.innerText = msg;
            t.className = `toast ${type}`;
            t.style.display = 'block';
            setTimeout(() => t.style.display = 'none', 3000);
        }

        // --- SUPPLIER LOGIC ---
        async function loadSuppliers() {
            const res = await fetch(`${API_PATH}/manage_suppliers.php`);
            const data = await res.json();
            
            // Populate Table
            const tbody = document.getElementById('supplierTable');
            tbody.innerHTML = data.map(s => `
                <tr>
                    <td>${s.company_name}</td>
                    <td>${s.contact_person || '-'} <br><small style="color:#666">${s.phone || ''}</small></td>
                    <td><i class="fa-solid fa-star" style="color:var(--gold)"></i> ${s.supplier_score}</td>
                    <td>
                        <button class="btn btn-gold btn-sm" onclick='openEdit(${JSON.stringify(s)})'><i class="fa-solid fa-pen"></i></button>
                        <button class="btn btn-danger btn-sm" onclick="deleteSupplier(${s.supplier_id})"><i class="fa-solid fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');

            // Populate Dropdown
            const select = document.getElementById('delSupplier');
            select.innerHTML = data.map(s => `<option value="${s.supplier_id}">${s.company_name}</option>`).join('');
        }

        // Add
        document.getElementById('addSupplierForm').onsubmit = async (e) => {
            e.preventDefault();
            const payload = {
                name: document.getElementById('supName').value,
                contact: document.getElementById('supContact').value,
                email: document.getElementById('supEmail').value,
                phone: document.getElementById('supPhone').value
            };
            const res = await fetch(`${API_PATH}/manage_suppliers.php`, { method: 'POST', body: JSON.stringify(payload) });
            const json = await res.json();
            if(json.status === 'success') { showToast('Supplier Added', 'success'); loadSuppliers(); e.target.reset(); }
        };

        // Edit
        function openEdit(s) {
            document.getElementById('editId').value = s.supplier_id;
            document.getElementById('editName').value = s.company_name;
            document.getElementById('editEmail').value = s.email;
            document.getElementById('editModal').style.display = 'flex';
        }
        function closeModal() { document.getElementById('editModal').style.display = 'none'; }
        
        async function updateSupplier() {
            const payload = {
                id: document.getElementById('editId').value,
                name: document.getElementById('editName').value,
                email: document.getElementById('editEmail').value
            };
            const res = await fetch(`${API_PATH}/manage_suppliers.php`, { method: 'PUT', body: JSON.stringify(payload) });
            const json = await res.json();
            if(json.status === 'success') { showToast('Updated Successfully', 'success'); closeModal(); loadSuppliers(); }
        }

        // Delete (Task 1.1.4)
        async function deleteSupplier(id) {
            if(confirm("Confirm Deletion? This cannot be undone.")) {
                const res = await fetch(`${API_PATH}/manage_suppliers.php?id=${id}`, { method: 'DELETE' });
                const json = await res.json();
                if(json.status === 'success') { showToast('Supplier Deleted', 'success'); loadSuppliers(); }
            }
        }

        // --- DELIVERY & STOCK LOGIC ---
        async function loadDeliveryHistory() {
            const res = await fetch(`${API_PATH}/process_delivery.php?action=list`);
            const data = await res.json();
            document.getElementById('deliveryTable').innerHTML = data.deliveries.map(d => `
                <tr>
                    <td>${d.delivery_date.split(' ')[0]}</td>
                    <td>${d.company_name || 'Unknown'}</td>
                    <td>${d.jewellery_type}</td>
                    <td style="color:var(--success)">+${d.quantity_received}</td>
                    <td><span style="color:var(--success)">Completed</span></td>
                </tr>
            `).join('');
            
            // Update Stock Ticker
            document.getElementById('stockTicker').innerHTML = data.stock.map(s => `
                <div class="ticker-item"><strong>${s.current_quantity}</strong> ${s.type}</div>
            `).join('');
        }

        document.getElementById('deliveryForm').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData();
            formData.append('supplier_id', document.getElementById('delSupplier').value);
            formData.append('jewellery_type', document.getElementById('delType').value);
            formData.append('quantity', document.getElementById('delQty').value);
            
            const file = document.getElementById('delFile').files[0];
            if(file) formData.append('invoice', file);

            try {
                const res = await fetch(`${API_PATH}/process_delivery.php`, { method: 'POST', body: formData });
                const json = await res.json();
                if(json.status === 'success') {
                    showToast(json.message, 'success'); // Task 1.3.2
                    loadDeliveryHistory();
                    e.target.reset();
                } else {
                    showToast(json.message, 'error'); // Task 1.3.3
                }
            } catch(err) { showToast('Connection Error', 'error'); }
        };

        // INIT
        loadSuppliers();
        loadDeliveryHistory();
    </script>
</body>
</html>