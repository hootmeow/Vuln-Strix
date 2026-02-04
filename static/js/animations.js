/**
 * Vuln-Strix Animations and Micro-interactions
 */

(function() {
    'use strict';

    // Counter Animation
    function animateCounter(element, start, end, duration, suffix = '') {
        if (start === end) {
            element.textContent = end + suffix;
            return;
        }

        const range = end - start;
        const startTime = performance.now();
        const isFloat = String(end).includes('.');

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Ease out quad for smoother animation
            const easeProgress = 1 - (1 - progress) * (1 - progress);
            const currentValue = start + (range * easeProgress);

            if (isFloat) {
                element.textContent = currentValue.toFixed(1) + suffix;
            } else {
                element.textContent = Math.round(currentValue) + suffix;
            }

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    // Initialize counters when they become visible
    function initCounters() {
        const counters = document.querySelectorAll('[data-counter]');

        if ('IntersectionObserver' in window) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const el = entry.target;
                        const target = parseFloat(el.dataset.counter);
                        const suffix = el.dataset.counterSuffix || '';
                        const duration = parseInt(el.dataset.counterDuration) || 1000;

                        animateCounter(el, 0, target, duration, suffix);
                        observer.unobserve(el);
                    }
                });
            }, { threshold: 0.1 });

            counters.forEach(counter => observer.observe(counter));
        } else {
            // Fallback for older browsers
            counters.forEach(el => {
                const target = parseFloat(el.dataset.counter);
                const suffix = el.dataset.counterSuffix || '';
                el.textContent = target + suffix;
            });
        }
    }

    // Ripple effect for buttons
    function initRippleEffect() {
        document.addEventListener('click', function(e) {
            const button = e.target.closest('.btn-ripple');
            if (!button) return;

            const ripple = document.createElement('span');
            const rect = button.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;

            ripple.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                left: ${x}px;
                top: ${y}px;
                background: rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                transform: scale(0);
                animation: ripple 0.6s ease-out;
                pointer-events: none;
            `;

            button.style.position = 'relative';
            button.style.overflow = 'hidden';
            button.appendChild(ripple);

            ripple.addEventListener('animationend', () => ripple.remove());
        });

        // Add ripple keyframes if not present
        if (!document.querySelector('#ripple-styles')) {
            const style = document.createElement('style');
            style.id = 'ripple-styles';
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(4);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }

    // Toast notifications
    function showToast(message, type = 'info', duration = 3000) {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast show fade-in`;
        toast.setAttribute('role', 'alert');

        const iconMap = {
            success: 'check-circle',
            error: 'alert-circle',
            warning: 'alert-triangle',
            info: 'info'
        };

        const colorMap = {
            success: '#198754',
            error: '#dc3545',
            warning: '#ffc107',
            info: '#0d6efd'
        };

        toast.innerHTML = `
            <div class="toast-body d-flex align-items-center gap-2">
                <span data-feather="${iconMap[type] || 'info'}" style="color: ${colorMap[type]}"></span>
                <span>${message}</span>
                <button type="button" class="btn-close ms-auto" aria-label="Close"></button>
            </div>
        `;

        container.appendChild(toast);

        // Initialize feather icons if available
        if (typeof feather !== 'undefined') {
            feather.replace();
        }

        // Close button
        toast.querySelector('.btn-close').addEventListener('click', () => {
            toast.classList.add('hiding');
            setTimeout(() => toast.remove(), 200);
        });

        // Auto-dismiss
        setTimeout(() => {
            if (toast.parentNode) {
                toast.classList.add('hiding');
                setTimeout(() => toast.remove(), 200);
            }
        }, duration);
    }

    // Loading state for buttons
    function setButtonLoading(button, loading = true) {
        if (loading) {
            button.dataset.originalText = button.innerHTML;
            button.disabled = true;
            button.innerHTML = `
                <span class="loading-spinner">
                    <span class="spinner"></span>
                    <span>Loading...</span>
                </span>
            `;
        } else {
            button.disabled = false;
            button.innerHTML = button.dataset.originalText || button.innerHTML;
        }
    }

    // Smooth scroll to element
    function scrollToElement(selector, offset = 80) {
        const element = document.querySelector(selector);
        if (element) {
            const top = element.getBoundingClientRect().top + window.pageYOffset - offset;
            window.scrollTo({ top, behavior: 'smooth' });
        }
    }

    // Filter table with animation
    function filterTable(tableSelector, searchTerm, columnIndex = null) {
        const table = document.querySelector(tableSelector);
        if (!table) return;

        const rows = table.querySelectorAll('tbody tr');
        const term = searchTerm.toLowerCase().trim();

        rows.forEach(row => {
            const cells = columnIndex !== null
                ? [row.cells[columnIndex]]
                : Array.from(row.cells);

            const text = cells.map(c => c.textContent.toLowerCase()).join(' ');
            const matches = !term || text.includes(term);

            if (matches) {
                row.style.display = '';
                row.classList.add('fade-in');
            } else {
                row.style.display = 'none';
            }
        });
    }

    // Debounce utility
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Initialize search inputs
    function initSearchInputs() {
        document.querySelectorAll('[data-search-table]').forEach(input => {
            const tableSelector = input.dataset.searchTable;
            const columnIndex = input.dataset.searchColumn
                ? parseInt(input.dataset.searchColumn)
                : null;

            input.addEventListener('input', debounce(function() {
                filterTable(tableSelector, this.value, columnIndex);
            }, 200));
        });
    }

    // Copy to clipboard with feedback
    function copyToClipboard(text, feedbackElement = null) {
        navigator.clipboard.writeText(text).then(() => {
            if (feedbackElement) {
                const originalText = feedbackElement.textContent;
                feedbackElement.textContent = 'Copied!';
                setTimeout(() => {
                    feedbackElement.textContent = originalText;
                }, 2000);
            }
            showToast('Copied to clipboard', 'success');
        }).catch(() => {
            showToast('Failed to copy', 'error');
        });
    }

    // Chart gradient helper
    function createChartGradient(ctx, startColor, endColor, height = 300) {
        const gradient = ctx.createLinearGradient(0, 0, 0, height);
        gradient.addColorStop(0, startColor);
        gradient.addColorStop(1, endColor);
        return gradient;
    }

    // Page transition effect
    function initPageTransitions() {
        // Fade in main content on page load
        const main = document.querySelector('main');
        if (main) {
            main.classList.add('fade-in');
        }

        // Add stagger effect to card grids
        document.querySelectorAll('.row > [class*="col-"]').forEach((col, index) => {
            if (col.querySelector('.card, .kpi-card')) {
                col.style.animationDelay = `${index * 0.05}s`;
                col.classList.add('stagger-item');
            }
        });
    }

    // Initialize all animations on DOM ready
    function init() {
        initCounters();
        initRippleEffect();
        initSearchInputs();
        initPageTransitions();
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose utilities globally
    window.VulnStrix = {
        animateCounter,
        showToast,
        setButtonLoading,
        scrollToElement,
        filterTable,
        debounce,
        copyToClipboard,
        createChartGradient
    };

})();
