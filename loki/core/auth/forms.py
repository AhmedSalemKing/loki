"""
Form detection and filling for SPAs (React, Vue, Angular).
Uses JavaScript evaluation for reliable detection.
Handles Dutch and English field labels.
"""
from __future__ import annotations
import asyncio
from typing import Optional
from playwright.async_api import Page


FORM_DETECTION_JS = """
() => {
    const forms = [];
    const allForms = document.querySelectorAll('form');
    const containers = allForms.length > 0 ? Array.from(allForms) : [document.body];

    containers.forEach((container, formIdx) => {
        const inputs = Array.from(container.querySelectorAll(
            'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="checkbox"]):not([type="radio"]), textarea'
        )).filter(el => {
            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return style.display !== 'none'
                && style.visibility !== 'hidden'
                && parseFloat(style.opacity) > 0
                && rect.width > 0
                && rect.height > 0;
        });

        if (inputs.length === 0) return;

        const fields = inputs.map(input => {
            let label = '';
            // Method 1: for/id association
            if (input.id) {
                const lbl = document.querySelector(`label[for="${input.id}"]`);
                if (lbl) label = lbl.textContent.trim();
            }
            // Method 2: ancestor label
            if (!label) {
                let p = input.parentElement;
                while (p && p !== document.body) {
                    if (p.tagName === 'LABEL') { label = p.textContent.trim(); break; }
                    const lbl = p.querySelector('label');
                    if (lbl && lbl.textContent.trim() && !lbl.querySelector('input')) {
                        label = lbl.textContent.trim(); break;
                    }
                    p = p.parentElement;
                }
            }
            // Method 3: aria-label, placeholder
            if (!label) label = input.getAttribute('aria-label') || '';
            if (!label) label = input.placeholder || '';

            // Build unique CSS selector
            let selector = '';
            if (input.id) selector = `#${CSS.escape(input.id)}`;
            else if (input.name) selector = `${input.tagName.toLowerCase()}[name="${input.name}"]`;
            else {
                const idx = Array.from(document.querySelectorAll('input')).indexOf(input);
                selector = `input:nth-of-type(${idx + 1})`;
            }

            return {
                selector,
                label: label.replace(/\\s+/g, ' ').substring(0, 100),
                placeholder: input.placeholder || '',
                input_type: input.type || 'text',
                autocomplete: input.autocomplete || '',
                name_attr: input.name || '',
                required: input.required || false,
            };
        });

        // Find submit button
        const submitSelectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:not([type])',
        ];
        let submitSelector = '';
        for (const sel of submitSelectors) {
            const btn = container.querySelector(sel);
            if (btn && window.getComputedStyle(btn).display !== 'none') {
                submitSelector = sel;
                break;
            }
        }
        // Fallback: button containing register/submit keywords
        if (!submitSelector) {
            const SUBMIT_WORDS = ['account aanmaken', 'registreer', 'aanmaken', 'sign up', 'register', 'submit', 'create', 'volgende', 'next'];
            Array.from(container.querySelectorAll('button, [role="button"]')).forEach(btn => {
                const text = btn.textContent.toLowerCase().trim();
                if (SUBMIT_WORDS.some(w => text.includes(w))) {
                    if (!submitSelector) submitSelector = btn.id ? `#${CSS.escape(btn.id)}` : 'button:last-of-type';
                }
            });
        }

        forms.push({
            form_index: formIdx,
            fields,
            submit_selector: submitSelector,
            action: container.tagName === 'FORM' ? (container.action || '') : '',
        });
    });
    return forms;
}
"""


async def detect_forms(page: Page) -> list[dict]:
    """
    Detect all visible forms on the page using JavaScript evaluation.
    Returns list of form dicts with fields and submit selector.
    """
    try:
        forms = await page.evaluate(FORM_DETECTION_JS)
        return forms or []
    except Exception as e:
        return []


async def fill_field(page: Page, selector: str, value: str) -> bool:
    """
    Fill a form field with React/Vue/Angular compatibility.
    Uses real typing simulation to trigger onChange/onBlur events.
    Returns True if value was successfully set.
    """
    import re
    try:
        el = page.locator(selector).first
        await el.wait_for(state="visible", timeout=5000)
        await el.click()
        await asyncio.sleep(0.1)
        # Select all existing text and delete
        await page.keyboard.press("Control+a")
        await asyncio.sleep(0.05)
        await page.keyboard.press("Backspace")
        await asyncio.sleep(0.05)
        # Type character by character to trigger React synthetic events
        await page.type(selector, value, delay=45)
        await asyncio.sleep(0.1)
        # Tab to trigger onBlur validation
        await page.keyboard.press("Tab")
        await asyncio.sleep(0.15)
        # Verify value was actually set
        actual = await page.evaluate(f"document.querySelector({selector!r})?.value")
        return actual == value
    except Exception:
        return False


async def click_submit(page: Page, submit_selector: str) -> None:
    """Click the form submit button."""
    try:
        btn = page.locator(submit_selector).first
        await btn.wait_for(state="visible", timeout=5000)
        await btn.click()
    except Exception:
        # Fallback: press Enter in the last input
        await page.keyboard.press("Enter")