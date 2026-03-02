// ═══════════════════════════════════════════
// SecureChain — main.js
// ═══════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

    // ── Scroll reveal ──────────────────────
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

    document.querySelectorAll('.card, .main-card, .feature-card, .stat-card, .table-container').forEach((el, i) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(22px)';
        el.style.transition = `opacity 0.55s cubic-bezier(0.4,0,0.2,1) ${i * 0.07}s, transform 0.55s cubic-bezier(0.4,0,0.2,1) ${i * 0.07}s`;
        observer.observe(el);
    });

    // ── Auto-dismiss flash alerts ──────────
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s, transform 0.4s';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-8px)';
            setTimeout(() => alert.remove(), 400);
        }, 5000);
    });

    // ── 6-digit code auto-format ───────────
    document.querySelectorAll('input[maxlength="6"]').forEach(input => {
        input.addEventListener('input', () => {
            input.value = input.value.replace(/\D/g, '').slice(0, 6);
        });
    });

    // ── Active nav highlight ───────────────
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});
