/**
 * AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
 * Frontend JavaScript: Validation, Presets, and UI Interactions
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Preset Data Definitions for Testing & Demonstration
    const samplePresets = {
        normal_dns: {
            proto: 'udp',
            service: 'dns',
            state: 'INT',
            dur: 0.000011,
            rate: 90909.09,
            sinpkt: 0.011,
            dinpkt: 0.0,
            sjit: 0.0,
            djit: 0.0,
            sbytes: 146,
            dbytes: 0,
            sload: 53090908.0,
            dload: 0.0,
            response_body_len: 0,
            stcpb: 0,
            dtcpb: 0,
            tcprtt: 0.0,
            synack: 0.0,
            ackdat: 0.0
        },
        normal_web: {
            proto: 'tcp',
            service: 'http',
            state: 'FIN',
            dur: 0.121478,
            rate: 74.087,
            sinpkt: 24.295,
            dinpkt: 40.492,
            sjit: 10.0,
            djit: 5.0,
            sbytes: 258,
            dbytes: 172,
            sload: 14158.94,
            dload: 8495.36,
            response_body_len: 0,
            stcpb: 621772692,
            dtcpb: 220197724,
            tcprtt: 0.000955,
            synack: 0.000577,
            ackdat: 0.000378
        },
        attack_exploit: {
            proto: 'tcp',
            service: 'http',
            state: 'FIN',
            dur: 0.921478,
            rate: 1200.5,
            sinpkt: 0.5,
            dinpkt: 0.4,
            sjit: 120.5,
            djit: 98.2,
            sbytes: 12580,
            dbytes: 172000,
            sload: 109200.0,
            dload: 1490000.0,
            response_body_len: 45000,
            stcpb: 621772692,
            dtcpb: 220197724,
            tcprtt: 0.125,
            synack: 0.065,
            ackdat: 0.060
        }
    };

    // 2. Preset Buttons Event Listener
    const presetButtons = document.querySelectorAll('[data-preset]');
    presetButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const presetKey = btn.getAttribute('data-preset');
            const data = samplePresets[presetKey];
            if (!data) return;

            Object.entries(data).forEach(([fieldName, val]) => {
                const input = document.getElementById(`id_${fieldName}`) || document.querySelector(`[name="${fieldName}"]`);
                if (input) {
                    input.value = val;
                    // Visual flash effect on filled inputs
                    input.style.borderColor = 'var(--primary-cyan)';
                    setTimeout(() => {
                        input.style.borderColor = '';
                    }, 500);
                }
            });
        });
    });

    // 3. Clear Form Button
    const resetBtn = document.getElementById('btn-reset-form');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            const form = document.getElementById('threat-detection-form');
            if (form) {
                form.reset();
            }
        });
    }

    // 4. Form Submission & Loading Overlay State
    const form = document.getElementById('threat-detection-form');
    const loadingOverlay = document.getElementById('loading-overlay');

    if (form) {
        form.addEventListener('submit', (e) => {
            let isValid = true;
            const requiredInputs = form.querySelectorAll('input[required], select[required]');

            requiredInputs.forEach(input => {
                if (!input.value.trim()) {
                    isValid = false;
                    input.style.borderColor = 'var(--color-attack)';
                } else {
                    input.style.borderColor = '';
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Please fill in all required network traffic features before analyzing.');
                return;
            }

            // Show loading animation overlay
            if (loadingOverlay) {
                loadingOverlay.style.display = 'flex';
            }
        });
    }

    // 5. Smooth scroll if requested
    const scrollToAbout = document.body.getAttribute('data-scroll-about');
    if (scrollToAbout === 'true') {
        const aboutEl = document.getElementById('about-section');
        if (aboutEl) {
            aboutEl.scrollIntoView({ behavior: 'smooth' });
        }
    }
});
