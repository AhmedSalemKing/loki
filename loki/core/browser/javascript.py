"""
React-compatible form filling + field discovery JS helpers.
"""

FILL_FIELD_JS = """
(selector, value) => {
    const el = document.querySelector(selector);
    if (!el) return false;
    // React/Vue controlled input pattern
    const nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    ) || Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
    );
    if (nativeSetter && nativeSetter.set) {
        nativeSetter.set.call(el, value);
    } else {
        el.value = value;
    }
    ['input','change','blur'].forEach(evt =>
        el.dispatchEvent(new Event(evt, {bubbles:true,cancelable:true}))
    );
    return true;
}
"""

SCAN_FORMS_JS = """
() => {
    const forms = [];
    document.querySelectorAll('form,[data-form],[role="form"]').forEach((form, fi) => {
        const fields = [];
        form.querySelectorAll('input,select,textarea').forEach(el => {
            if (el.type === 'hidden' || el.type === 'submit' || el.type === 'button') return;
            const label = (() => {
                if (el.id) {
                    const l = document.querySelector(`label[for="${el.id}"]`);
                    if (l) return l.innerText.trim();
                }
                const closest = el.closest('label');
                if (closest) return closest.innerText.trim();
                const prev = el.previousElementSibling;
                if (prev && ['LABEL','SPAN','P','DIV'].includes(prev.tagName))
                    return prev.innerText.trim().substring(0,60);
                return '';
            })();
            fields.push({
                tag: el.tagName.toLowerCase(),
                type: el.type || '',
                name: el.name || '',
                id: el.id || '',
                placeholder: el.placeholder || '',
                autocomplete: el.autocomplete || '',
                ariaLabel: el.getAttribute('aria-label') || '',
                label: label,
                selector: el.id ? `#${el.id}` :
                          el.name ? `[name="${el.name}"]` :
                          `form:nth-of-type(${fi+1}) input:nth-of-type(${fields.length+1})`,
                required: el.required,
                visible: el.offsetParent !== null
            });
        });
        const submitBtn = form.querySelector('[type=submit],button:not([type=button])');
        forms.push({
            index: fi,
            action: form.action || '',
            method: (form.method || 'get').toUpperCase(),
            fields: fields,
            submitSelector: submitBtn ? (
                submitBtn.id ? `#${submitBtn.id}` : '[type=submit]'
            ) : null,
            submitText: submitBtn ? submitBtn.innerText.trim() : ''
        });
    });
    return forms;
}
"""

DETECT_AUTH_STATE_JS = """
() => {
    const html = document.documentElement.innerHTML.toLowerCase();
    const url = location.href.toLowerCase();
    // Success signals
    const successWords = ['dashboard','account','profile','mijn','uitloggen',
                          'logout','sign out','welkom','welcome','hallo'];
    const errorWords = ['invalid','incorrect','wrong','error','failed',
                        'onjuist','verkeerd','fout'];
    const otpWords = ['otp','verification code','6-digit','sms code',
                      'verify your','bevestig'];
    const captchaWords = ['captcha','i am not a robot','recaptcha'];
    const emailVerifyWords = ['check your email','verify your email',
                               'bevestig je e-mail','verification link'];
    const score = w => w.filter(kw => html.includes(kw) || url.includes(kw)).length;
    return {
        success:      score(successWords),
        error:        score(errorWords),
        otp:          score(otpWords),
        captcha:      score(captchaWords),
        emailVerify:  score(emailVerifyWords),
        url:          location.href,
        title:        document.title
    };
}
"""

PAGE_TYPE_JS = """
() => {
    const html = document.documentElement.innerHTML.toLowerCase();
    const registerWords = ['registreer','register','sign up','create account',
                           'aanmelden','join','new account'];
    const loginWords    = ['inloggen','login','sign in','log in','aanmelden'];
    const passwordFields = document.querySelectorAll('input[type=password]').length;
    const emailFields    = document.querySelectorAll(
        'input[type=email],[name*=email],[name*=mail],[placeholder*=email],[placeholder*=mail]'
    ).length;
    const confirmPass = html.includes('confirm') || html.includes('bevestig') ||
                        html.includes('herhaal') || html.includes('repeat');
    const regScore = registerWords.filter(w=>html.includes(w)).length * 20
                   + (confirmPass ? 25 : 0)
                   + (passwordFields >= 2 ? 20 : 0)
                   + (emailFields > 0 ? 15 : 0);
    const loginScore = loginWords.filter(w=>html.includes(w)).length * 20
                     + (passwordFields === 1 ? 20 : 0)
                     + (emailFields > 0 ? 10 : 0)
                     + (confirmPass ? -20 : 0);
    return {
        registerConfidence: Math.min(regScore, 100),
        loginConfidence: Math.min(loginScore, 100),
        passwordFields,
        emailFields,
        confirmPassword: confirmPass,
        url: location.href,
        title: document.title
    };
}
"""
