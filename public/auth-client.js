(() => {
  const apiBase = '';
  let authMode = 'signin';
  let authHydrated = false;

  function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    const isJSONBody = options.body && typeof options.body === 'string';
    if (isJSONBody && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    return fetch(`${apiBase}${path}`, {
      credentials: 'include',
      ...options,
      headers
    });
  }

  async function readJSON(res) {
    const text = await res.text();
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      return { message: text || 'Response tidak valid.' };
    }
  }

  function setAuthStatus(message, type = 'info') {
    const node = el('auth-status');
    if (!node) return;
    node.className = `auth-status ${type}`;
    node.textContent = message;
  }

  function setActiveAuthTab(mode) {
    authMode = mode;
    document.querySelectorAll('[data-auth-tab]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.authTab === mode);
    });
    document.querySelectorAll('[data-auth-panel]').forEach((panel) => {
      panel.classList.toggle('active', panel.dataset.authPanel === mode);
      panel.classList.toggle('hidden', panel.dataset.authPanel !== mode);
    });
    if (mode === 'signin') setAuthStatus('Masuk pakai email dan password.', 'info');
    if (mode === 'signup') setAuthStatus('Daftar akun baru, lalu verifikasi OTP dari email.', 'info');
    if (mode === 'verify') setAuthStatus('Masukkan OTP yang dikirim ke email untuk aktifkan akun.', 'info');
    if (mode === 'reset') setAuthStatus('Masukkan OTP reset untuk mengganti password.', 'info');
  }

  function openAuthModal(mode = 'signin') {
    setActiveAuthTab(mode);
    openModal('auth-modal');
  }

  function fillProfileFromUser(user) {
    state.loggedIn = true;
    state.currentUser = user?.name || '';
    state.profileBio = user?.bio || '';
    state.profileAvatar = user?.avatar_url || '';
    updateAuthUI();
    setProfilePreview(state.profileAvatar || '');
  }

  async function fetchMeAndOrders() {
    const meRes = await api('/api/me');
    if (meRes.status === 401) {
      state.loggedIn = false;
      state.currentUser = '';
      state.profileBio = '';
      state.profileAvatar = '';
      state.orders = [];
      updateAuthUI();
      renderHistory();
      setProfilePreview('');
      return null;
    }

    if (!meRes.ok) {
      const payload = await readJSON(meRes);
      throw new Error(payload.message || 'Gagal mengambil profil.');
    }

    const payload = await readJSON(meRes);
    if (payload?.user) {
      fillProfileFromUser(payload.user);
    }

    const ordersRes = await api('/api/me/orders');
    if (ordersRes.ok) {
      const ordersPayload = await readJSON(ordersRes);
      state.orders = Array.isArray(ordersPayload.orders) ? ordersPayload.orders : [];
      renderHistory();
    }

    return payload?.user || null;
  }

  async function hydrateAuthSession() {
    if (authHydrated) return;
    authHydrated = true;
    try {
      await fetchMeAndOrders();
    } catch (error) {
      console.warn('Auth hydration skipped:', error);
    }
  }

  function getSigninPayload() {
    const email = el('auth-signin-email')?.value.trim().toLowerCase();
    const password = el('auth-signin-password')?.value || '';
    return { email, password };
  }

  function getSignupPayload() {
    const name = el('auth-signup-name')?.value.trim();
    const email = el('auth-signup-email')?.value.trim().toLowerCase();
    const password = el('auth-signup-password')?.value || '';
    const confirm = el('auth-signup-confirm')?.value || '';
    return { name, email, password, confirm };
  }

  function getResetPayload() {
    const email = el('auth-reset-email')?.value.trim().toLowerCase();
    const otp = el('auth-reset-otp')?.value.trim();
    const password = el('auth-reset-password')?.value || '';
    const confirm = el('auth-reset-confirm')?.value || '';
    return { email, otp, password, confirm };
  }

  async function login() {
    const { email, password } = getSigninPayload();
    if (!email || !password) {
      showToast('Isi email dan password dulu.', 'error');
      setAuthStatus('Email dan password wajib diisi.', 'error');
      return;
    }

    const res = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    const payload = await readJSON(res);

    if (!res.ok) {
      setAuthStatus(payload.message || 'Login gagal.', 'error');
      showToast(payload.message || 'Login gagal.', 'error');
      return;
    }

    fillProfileFromUser(payload.user);
    await fetchMeAndOrders();
    closeModal('auth-modal');
    showToast(`Login berhasil, ${payload.user?.name || 'Pengguna'}!`, 'success');
  }

  async function signup() {
    const { name, email, password, confirm } = getSignupPayload();
    if (!name || !email || !password) {
      setAuthStatus('Nama, email, dan password wajib diisi.', 'error');
      showToast('Lengkapi data pendaftaran dulu.', 'error');
      return;
    }
    if (password !== confirm) {
      setAuthStatus('Password dan konfirmasi tidak sama.', 'error');
      showToast('Password tidak cocok.', 'error');
      return;
    }

    const res = await api('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password })
    });
    const payload = await readJSON(res);

    if (!res.ok) {
      setAuthStatus(payload.message || 'Gagal daftar.', 'error');
      showToast(payload.message || 'Gagal daftar.', 'error');
      return;
    }

    setAuthStatus(payload.message || 'OTP sudah dikirim ke email.', 'success');
    showToast(payload.message || 'OTP sudah dikirim ke email.', 'success');
    const verifyEmail = el('auth-verify-email');
    if (verifyEmail) verifyEmail.value = email;
    const otpInput = el('auth-verify-otp');
    if (otpInput) otpInput.value = '';
    setActiveAuthTab('verify');
    if (!payload.autoVerified) {
      showToast('Cek email untuk OTP verifikasi.', 'info');
    }
  }

  async function verifySignup() {
    const email = el('auth-verify-email')?.value.trim().toLowerCase();
    const otp = el('auth-verify-otp')?.value.trim();
    if (!email || !otp) {
      setAuthStatus('Email dan OTP wajib diisi.', 'error');
      showToast('Email dan OTP wajib diisi.', 'error');
      return;
    }

    const res = await api('/api/auth/verify-register', {
      method: 'POST',
      body: JSON.stringify({ email, otp })
    });
    const payload = await readJSON(res);

    if (!res.ok) {
      setAuthStatus(payload.message || 'OTP verifikasi salah.', 'error');
      showToast(payload.message || 'OTP verifikasi salah.', 'error');
      return;
    }

    fillProfileFromUser(payload.user);
    await fetchMeAndOrders();
    closeModal('auth-modal');
    showToast('Akun berhasil diverifikasi dan login aktif.', 'success');
  }

  async function requestResetOtp() {
    const email = el('auth-reset-email')?.value.trim().toLowerCase();
    if (!email) {
      setAuthStatus('Email wajib diisi untuk kirim OTP reset.', 'error');
      showToast('Isi email dulu.', 'error');
      return;
    }

    const res = await api('/api/auth/request-password-reset', {
      method: 'POST',
      body: JSON.stringify({ email })
    });
    const payload = await readJSON(res);

    if (!res.ok) {
      setAuthStatus(payload.message || 'Gagal kirim OTP reset.', 'error');
      showToast(payload.message || 'Gagal kirim OTP reset.', 'error');
      return;
    }

    setAuthStatus(payload.message || 'OTP reset sudah dikirim.', 'success');
    showToast(payload.message || 'OTP reset sudah dikirim.', 'success');
    const otpInput = el('auth-reset-otp');
    if (otpInput) otpInput.focus();
    setActiveAuthTab('reset');
  }

  async function resetPassword() {
    const { email, otp, password, confirm } = getResetPayload();
    if (!email || !otp || !password) {
      setAuthStatus('Email, OTP, dan password baru wajib diisi.', 'error');
      showToast('Lengkapi data reset password.', 'error');
      return;
    }
    if (password !== confirm) {
      setAuthStatus('Password baru dan konfirmasi tidak sama.', 'error');
      showToast('Password baru tidak cocok.', 'error');
      return;
    }

    const res = await api('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ email, otp, password })
    });
    const payload = await readJSON(res);

    if (!res.ok) {
      setAuthStatus(payload.message || 'Reset password gagal.', 'error');
      showToast(payload.message || 'Reset password gagal.', 'error');
      return;
    }

    setAuthStatus(payload.message || 'Password berhasil diganti.', 'success');
    showToast(payload.message || 'Password berhasil diganti.', 'success');
    setActiveAuthTab('signin');
  }

  async function saveProfileToServer() {
    const name = el('profile-username')?.value.trim();
    const bio = el('profile-bio')?.value.trim() || '';
    if (!name) {
      showToast('Nama profil tidak boleh kosong.', 'error');
      return null;
    }
    const file = getProfileUploadFile();
    let avatar = state.profileAvatar || '';

    if (file) {
      avatar = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ''));
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    }

    const res = await api('/api/me/profile', {
      method: 'PUT',
      body: JSON.stringify({ name, bio, avatar_url: avatar || '' })
    });
    const payload = await readJSON(res);

    if (!res.ok) {
      showToast(payload.message || 'Gagal simpan profil.', 'error');
      return null;
    }

    state.currentUser = payload.user?.name || name;
    state.profileBio = payload.user?.bio || bio;
    state.profileAvatar = payload.user?.avatar_url || avatar || '';
    updateAuthUI();
    setProfilePreview(state.profileAvatar || '');
    renderHistory();
    showToast('Profil berhasil disimpan ke database.', 'success');
    closeModal('profile-modal');
    return payload.user || null;
  }

  async function openProfileModalPatched() {
    if (!state.loggedIn) {
      openAuthModal('signin');
      showToast('Login dulu untuk buka profil.', 'error');
      return;
    }

    try {
      await fetchMeAndOrders();
    } catch (error) {
      console.warn(error);
    }

    const nameInput = el('profile-username');
    const bioInput = el('profile-bio');
    const modalName = el('profile-modal-name');
    const modalStatus = el('profile-modal-status');
    const orderCount = el('profile-order-count');
    const orderTotal = el('profile-order-total');

    if (nameInput) nameInput.value = state.currentUser || '';
    if (bioInput) bioInput.value = state.profileBio || '';
    if (modalName) modalName.textContent = state.currentUser || 'Pengguna';
    if (modalStatus) modalStatus.textContent = 'Profil kamu tersimpan di database.';
    if (orderCount) orderCount.textContent = String(Array.isArray(state.orders) ? state.orders.length : 0);
    const totalSpent = Array.isArray(state.orders) ? state.orders.reduce((sum, order) => sum + (Number(order.total) || 0), 0) : 0;
    if (orderTotal) orderTotal.textContent = formatPrice(totalSpent);
    setProfilePreview(state.profileAvatar || '');
    openModal('profile-modal');
  }

  function renderHistoryPatched() {
    const wrap = el('history-list');
    if (!wrap) return;

    if (!state.loggedIn) {
      wrap.innerHTML = '<div class="history-item"><h4>Login dulu</h4><p>Riwayat pemesanan ada di akun kamu setelah masuk.</p></div>';
      return;
    }

    if (!Array.isArray(state.orders) || !state.orders.length) {
      wrap.innerHTML = '<div class="history-item"><h4>Belum ada riwayat</h4><p>Pesanan yang selesai akan muncul di sini.</p></div>';
      return;
    }

    wrap.innerHTML = state.orders
      .slice()
      .sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
      .map((order) => {
        const reviewText = order.review
          ? `Rating ${order.review.restaurant || 0}/5 restoran, ${order.review.driver || 0}/5 driver.`
          : 'Belum ada rating.';
        return `
          <div class="history-item">
            <h4>${escapeHTML(order.itemLabel || 'Pesanan')}</h4>
            <p>#${escapeHTML(String(order.id))} • ${escapeHTML(order.time || '')}</p>
            <p>Total: ${formatPrice(order.total || 0)} • ${escapeHTML(order.status || 'Selesai')}</p>
            <p>${escapeHTML(reviewText)}</p>
            <div class="history-actions">
              <button class="btn btn-soft" type="button" data-history-receipt="${escapeHTML(String(order.id))}">Lihat bukti</button>
              <button class="btn btn-outline" type="button" data-history-delete="${escapeHTML(String(order.id))}">Hapus</button>
            </div>
          </div>
        `;
      })
      .join('');

    wrap.querySelectorAll('[data-history-receipt]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = Number(btn.dataset.historyReceipt);
        const order = state.orders.find((item) => Number(item.id) === id);
        if (order) openReceiptModal(order);
      });
    });

    wrap.querySelectorAll('[data-history-delete]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = Number(btn.dataset.historyDelete);
        if (!Number.isNaN(id)) await deleteOrderById(id);
      });
    });
  }

  async function deleteOrderByIdPatched(orderId) {
    const index = state.orders.findIndex((order) => Number(order.id) === Number(orderId));
    if (index < 0) return false;

    state.orders.splice(index, 1);
    renderHistoryPatched();
    saveState();

    api(`/api/orders/${encodeURIComponent(orderId)}`, { method: 'DELETE' }).catch(() => {});
    const receipt = el('receipt-modal');
    if (receipt?.classList.contains('show')) closeModal('receipt-modal');
    showToast('Riwayat pesanan dihapus dari database.', 'success');
    return true;
  }

  function finalizeDeliveredOrderPatched(orderDraft, driver, gps) {
    const order = {
      id: Date.now(),
      items: orderDraft.items,
      itemLabel: orderDraft.items.map((i) => i.name).join(', '),
      qty: orderDraft.qty,
      paymentMethod: orderDraft.paymentMethod,
      promoCode: orderDraft.promoCode,
      discountAmount: orderDraft.discountAmount,
      shippingVoucher: orderDraft.shippingVoucher,
      shippingBase: orderDraft.shippingBase,
      shippingDiscount: orderDraft.shippingDiscount,
      shippingFinal: orderDraft.shippingFinal,
      proof: orderDraft.proof,
      total: orderDraft.total,
      time: new Date().toLocaleString('id-ID'),
      status: 'Selesai Diantarkan',
      driverName: driver.name,
      driverVehicle: driver.bike,
      driverPlate: driver.plate,
      gpsLabel: gps.source === 'gps' ? `GPS aktif (${gps.accuracy ? `${Math.round(gps.accuracy)}m` : 'akurasi perangkat'})` : 'Perkiraan lokasi',
      locationName: deliveryLocationLabel || 'Lokasi tujuan',
      location: `${gps.lat.toFixed(5)}, ${gps.lng.toFixed(5)}`,
      review: null,
      supportLocked: false,
      supportOutcome: null,
      supportStartedAt: null,
      supportResolvedAt: null
    };

    state.orders.unshift(order);
    state.reviewTargetId = order.id;
    renderHistoryPatched();
    saveState();

    api('/api/orders', {
      method: 'POST',
      body: JSON.stringify(order)
    })
      .then(async (res) => {
        if (!res.ok) return;
        const payload = await readJSON(res);
        if (payload?.order) {
          const idx = state.orders.findIndex((item) => Number(item.id) === Number(order.id));
          if (idx >= 0) state.orders[idx] = payload.order;
          renderHistoryPatched();
        }
      })
      .catch(() => {});

    return order;
  }

  async function submitReviewPatched() {
    if (!state.reviewTargetId) {
      showToast('Data order tidak ditemukan.', 'error');
      return;
    }
    if (state.reviewDraft.restaurant < 1 || state.reviewDraft.driver < 1) {
      showToast('Beri rating restoran dan driver dulu.', 'error');
      return;
    }

    const order = state.orders.find((o) => Number(o.id) === Number(state.reviewTargetId));
    if (!order) {
      showToast('Order tidak ditemukan.', 'error');
      return;
    }

    order.review = {
      restaurant: state.reviewDraft.restaurant,
      driver: state.reviewDraft.driver,
      issue: el('review-issue')?.value || 'Pesanan lengkap dan enak',
      note: el('review-note')?.value.trim() || '',
      time: new Date().toLocaleString('id-ID')
    };

    saveState();
    renderHistoryPatched();
    closeModal('review-modal');
    showToast('Rating berhasil dikirim.', 'success');
    state.reviewTargetId = null;
    state.pendingReviewOrder = null;

    api(`/api/orders/${encodeURIComponent(order.id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ review: order.review })
    }).catch(() => {});
  }

  async function logoutPatched() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch {}
    state.loggedIn = false;
    state.currentUser = '';
    state.profileBio = '';
    state.profileAvatar = '';
    state.orders = [];
    updateAuthUI();
    renderHistoryPatched();
    closeModal('profile-modal');
    showToast('Logout berhasil.', 'success');
  }

  function patchGlobals() {
    window.login = login;
    window.logout = logoutPatched;
    window.openProfileModal = openProfileModalPatched;
    window.applyProfileChanges = saveProfileToServer;
    window.renderHistory = renderHistoryPatched;
    window.finalizeDeliveredOrder = finalizeDeliveredOrderPatched;
    window.deleteOrderById = deleteOrderByIdPatched;
    window.submitReview = submitReviewPatched;
    window.openAuthModal = openAuthModal;
  }

  function bindAuthUi() {
    document.querySelectorAll('[data-auth-tab]').forEach((btn) => {
      btn.addEventListener('click', () => setActiveAuthTab(btn.dataset.authTab || 'signin'));
    });

    el('signup-submit')?.addEventListener('click', signup);
    el('verify-signup-btn')?.addEventListener('click', verifySignup);
    el('verify-resend-btn')?.addEventListener('click', requestResetOtp);
    el('reset-request-btn')?.addEventListener('click', requestResetOtp);
    el('reset-password-btn')?.addEventListener('click', resetPassword);
    el('open-reset-auth')?.addEventListener('click', () => openAuthModal('reset'));
    el('back-to-signin-auth')?.addEventListener('click', () => openAuthModal('signin'));
  }

  function patchButtonHooks() {
    el('login-submit')?.addEventListener('click', login);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    patchGlobals();
    bindAuthUi();
    patchButtonHooks();
    await hydrateAuthSession();

    if (state.loggedIn) {
      updateAuthUI();
      renderHistoryPatched();
    }

    const avatar = state.profileAvatar || '';
    setProfilePreview(avatar);
  });

  patchGlobals();
  bindAuthUi();
})();
