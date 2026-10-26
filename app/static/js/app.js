(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const csrf = () => ($('input[name="csrf"]') || {}).value || "";
  const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");

  $$("[data-toggle-pw]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.togglePw);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-pressed", String(show));
    });
  });
  $$('input[type="password"]').forEach((input) => {
    const caps = $(".caps", input.closest(".field") || document.body);
    if (!caps) return;
    const check = (e) => { caps.hidden = !(e.getModifierState && e.getModifierState("CapsLock")); };
    input.addEventListener("keydown", check);
    input.addEventListener("keyup", check);
    input.addEventListener("blur", () => { caps.hidden = true; });
  });
  $$("[data-strength]").forEach((input) => {
    const meter = document.getElementById(input.dataset.strength);
    const bar = $(".meter__bar", meter), label = $(".meter__label", meter);
    const levels = [
      ["Too short", "var(--danger)", 15], ["Weak", "var(--danger)", 35],
      ["Fair", "var(--sun)", 60], ["Strong", "var(--ok)", 85], ["Very strong", "var(--ok)", 100],
    ];
    input.addEventListener("input", () => {
      const v = input.value;
      if (!v) { label.textContent = ""; bar.style.setProperty("--pct", "0%"); return; }
      let score = 0;
      if (v.length >= 12) {
        score = 1;
        const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
        if (v.length >= 16) score++;
        if (v.length >= 20 || kinds >= 3) score++;
        if (new Set(v).size >= 10 && (kinds >= 3 || v.length >= 24)) score++;
      }
      const [text, color, pct] = levels[score];
      label.textContent = text;
      bar.style.setProperty("--pct", pct + "%");
      bar.style.setProperty("--meter", color);
    });
  });

  $$("[data-digits]").forEach((input) => {
    input.addEventListener("input", () => {
      input.value = input.value.replace(/\D/g, "").slice(0, Number(input.dataset.digits));
    });
  });

  $$("form[data-upload]").forEach((form) => {
    const input = $(".drop__input", form), drop = $(".drop", form);
    const more = $(".upload__more", form), picked = $(".picked", form);
    const err = $(".upload__error", form), prog = $(".progress", form);
    const bar = $("progress", prog), plabel = $(".progress__label", form);
    const exts = form.dataset.exts.split(","), maxBytes = Number(form.dataset.maxMb) * 1048576;
    let file = null;

    const reset = () => {
      file = null; input.value = ""; more.hidden = true; picked.hidden = true; err.textContent = ""; drop.hidden = false;
    };
    const choose = (f) => {
      err.textContent = "";
      if (!f) return reset();
      const ext = (f.name.split(".").pop() || "").toLowerCase();
      if (!exts.includes(ext)) {
        reset();
        err.textContent = `.${ext} files are not accepted here. Use ${exts.join(", ").toUpperCase()}.`;
        return;
      }
      if (f.size === 0) { reset(); err.textContent = "This file is empty."; return; }
      if (f.size > maxBytes) {
        reset();
        err.textContent = `This file is ${fmtSize(f.size)}, above the ${form.dataset.maxMb} MB limit.`;
        return;
      }
      file = f;
      $(".picked__ext", picked).textContent = ext.toUpperCase();
      $(".picked__name", picked).textContent = f.name;
      $(".picked__size", picked).textContent = fmtSize(f.size) + ", ready to encrypt";
      picked.hidden = false;
      more.hidden = false;
      drop.hidden = true;
      $("#desc", form).focus();
    };

    input.addEventListener("change", () => choose(input.files[0]));
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.add("is-over")));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("is-over")));
    $("[data-upload-cancel]", form).addEventListener("click", reset);

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (!file) { err.textContent = "Choose a file first."; return; }
      const xhr = new XMLHttpRequest();
      xhr.open("POST", form.dataset.upload);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.setRequestHeader("X-CSRF-Token", csrf());
      xhr.setRequestHeader("X-Filename", encodeURIComponent(file.name));
      xhr.setRequestHeader("X-Description", encodeURIComponent($("#desc", form).value));
      $$("button", form).forEach((b) => (b.disabled = true));
      prog.hidden = false;
      xhr.upload.addEventListener("progress", (ev) => {
        if (!ev.lengthComputable) return;
        const pct = Math.round((ev.loaded / ev.total) * 100);
        bar.value = pct;
        plabel.textContent = pct < 100 ? `Uploading and encrypting, ${pct}%` : "Sealing the last piece...";
      });
      xhr.addEventListener("load", () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText); } catch (_) { }
        if (xhr.status === 200 && data.ok) { window.location.assign(data.url); return; }
        prog.hidden = true;
        $$("button", form).forEach((b) => (b.disabled = false));
        err.textContent = data.error || (xhr.status === 401 ? "Your session ended. Reload the page and sign in again."
                                                          : "The upload failed. Please try again.");
      });
      xhr.addEventListener("error", () => {
        prog.hidden = true;
        $$("button", form).forEach((b) => (b.disabled = false));
        err.textContent = "The connection dropped during the upload. Please try again.";
      });
      xhr.send(file);
    });
  });

  $$("[data-filter]").forEach((input) => {
    const list = document.getElementById(input.dataset.filter);
    const none = list.parentElement.querySelector(".no-match");
    input.addEventListener("input", () => {
      const q = input.value.trim().toLowerCase();
      let shown = 0;
      $$("[data-search]", list).forEach((li) => {
        const hit = !q || li.dataset.search.includes(q);
        li.hidden = !hit;
        if (hit) shown++;
      });
      if (none) none.hidden = shown > 0;
    });
  });

  $$("[data-verify]").forEach((btn) => {
    const out = $(".integrity__result", btn.parentElement);
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      out.className = "integrity__result";
      out.textContent = "Decrypting and checking every piece...";
      try {
        const r = await fetch(btn.dataset.verify, { method: "POST", headers: { "X-CSRF-Token": csrf() } });
        const d = await r.json();
        if (d.ok) {
          out.classList.add("is-ok");
          out.textContent = `Intact. ${d.chunks} piece${d.chunks > 1 ? "s" : ""} passed AES-GCM verification and the SHA-256 matches exactly (${d.seconds} s).`;
        } else {
          out.classList.add("is-bad");
          out.textContent = d.error || "The SHA-256 differs from the one recorded at upload. The file is not intact.";
        }
      } catch (_) {
        out.classList.add("is-bad");
        out.textContent = "The check could not run. Reload the page and try again.";
      }
      btn.disabled = false;
    });
  });

  $$("[data-open-dialog]").forEach((btn) => {
    const dlg = document.getElementById(btn.dataset.openDialog);
    btn.addEventListener("click", () => dlg.showModal());
    $$("[data-close-dialog]", dlg).forEach((c) => c.addEventListener("click", () => dlg.close()));
  });

  $$("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = document.getElementById(btn.dataset.copy).textContent.trim();
      const label = $("span", btn) || btn;
      try { await navigator.clipboard.writeText(text); label.textContent = "Copied"; }
      catch (_) { label.textContent = "Copy it manually"; }
    });
  });
  $$("[data-download-text]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const text = document.getElementById(btn.dataset.downloadText).textContent.trim();
      const blob = new Blob([`RekamKu recovery code\n${text}\n\nKeep it somewhere safe. Never share it.\n`],
                            { type: "text/plain" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = btn.dataset.filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });
  });
  $$("[data-enables]").forEach((box) => {
    const target = document.getElementById(box.dataset.enables);
    const sync = () => {
      target.classList.toggle("is-disabled", !box.checked);
      target.setAttribute("aria-disabled", String(!box.checked));
    };
    box.addEventListener("change", sync);
    sync();
  });
})();
