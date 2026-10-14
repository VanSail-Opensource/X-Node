(() => {
  "use strict";
  const data = window.XNODE_DOCS;
  if (!data || !Array.isArray(data.pages)) return;
  const pages = data.pages;
  const byKey = new Map(pages.map((page) => [page.key, page]));
  const find = (id) => document.getElementById(id);
  const article = find("article");
  const body = find("page-body");
  const sidebar = find("sidebar");
  const backdrop = document.querySelector(".sidebar-backdrop");
  const menuButton = find("menu-button");
  const input = find("search");
  const results = find("search-results");
  const navigation = find("navigation");
  let currentKey = "";
  let observer;
  let toastTimeout;

  function toggleMenu(open) {
    const wasOpen = sidebar.classList.contains("open");
    const mobile = window.matchMedia("(max-width: 850px)").matches;
    sidebar.classList.toggle("open", open);
    sidebar.inert = mobile && !open;
    backdrop.hidden = !open;
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    document.body.classList.toggle("menu-open", open);
    if (open) input.focus();
    else if (wasOpen) menuButton.focus();
  }

  function notify(message) {
    const notification = find("notification");
    notification.textContent = message;
    notification.hidden = false;
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => { notification.hidden = true; }, 2200);
  }

  function syntaxHighlight() {
    body.querySelectorAll(".code-block").forEach((block) => {
      if (block.querySelector(".code-toolbar > span").textContent !== "json") return;
      const code = block.querySelector("pre code");
      const source = code.textContent;
      const pattern = /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g;
      const fragment = document.createDocumentFragment();
      let cursor = 0;
      for (const match of source.matchAll(pattern)) {
        fragment.append(document.createTextNode(source.slice(cursor, match.index)));
        const span = document.createElement("span");
        const token = match[0];
        span.className = token.startsWith('"') ? (/^\s*:/.test(source.slice(match.index + token.length)) ? "syntax-key" : "syntax-string") : (/^(true|false|null)$/.test(token) ? "syntax-literal" : "syntax-number");
        span.textContent = token;
        fragment.append(span);
        cursor = match.index + token.length;
      }
      fragment.append(document.createTextNode(source.slice(cursor)));
      code.replaceChildren(fragment);
    });
  }

  function outline(page) {
    if (observer) observer.disconnect();
    const target = find("outline");
    target.replaceChildren();
    const headings = [...body.querySelectorAll("h2[id], h3[id]")];
    const links = new Map();
    headings.forEach((heading) => {
      const link = document.createElement("a");
      link.href = "#/" + page.key + "?section=" + encodeURIComponent(heading.id);
      link.textContent = heading.textContent;
      link.addEventListener("click", (event) => {
        event.preventDefault();
        history.replaceState(null, "", link.href);
        heading.scrollIntoView({ block: "start" });
      });
      target.append(link);
      links.set(heading.id, link);
    });
    if (typeof IntersectionObserver !== "undefined") {
      observer = new IntersectionObserver((entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (!visible.length) return;
        links.forEach((link) => link.classList.remove("active"));
        const active = links.get(visible[0].target.id);
        if (active) active.classList.add("active");
      }, { rootMargin: "-75px 0px -65% 0px" });
      headings.forEach((heading) => observer.observe(heading));
    }
  }

  function render() {
    const raw = location.hash.replace(/^#\/?/, "") || "overview";
    const [key, query] = raw.split("?", 2);
    const page = byKey.get(key) || byKey.get("overview");
    const index = pages.indexOf(page);
    const changed = currentKey !== page.key;
    currentKey = page.key;
    document.title = page.title + " · X-Node API reference";
    find("breadcrumb").textContent = page.group;
    find("page-group").textContent = page.group.toUpperCase();
    find("page-number").textContent = String(index + 1).padStart(2, "0");
    find("page-title").textContent = page.title;
    find("page-description").textContent = page.description;
    article.classList.toggle("reference", Boolean(page.kind));
    find("overview-cards").hidden = page.key !== "overview";
    const badges = find("page-badges");
    badges.replaceChildren();
    if (page.kind) {
      for (const [label, type] of [[page.kind === "command" ? "COMMAND" : "MESSAGE", "type"], [page.direction, "direction"]]) {
        const badge = document.createElement("span");
        badge.className = "badge " + type;
        badge.textContent = label;
        badges.append(badge);
      }
    }
    // HTML is generated from repository source by build_docs.py, never user input.
    body.innerHTML = page.body;
    navigation.querySelectorAll("a[data-page]").forEach((link) => {
      const active = link.dataset.page === page.key;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    for (const [id, adjacent] of [["previous-page", pages[index - 1]], ["next-page", pages[index + 1]]]) {
      const link = find(id);
      link.setAttribute("aria-disabled", String(!adjacent));
      link.tabIndex = adjacent ? 0 : -1;
      link.href = "#/" + (adjacent ? adjacent.key : "overview");
      link.querySelector("strong").textContent = adjacent ? adjacent.title : "";
    }
    find("source-link").href = data.repo + (page.key.startsWith("guides/") ? "/blob/main/docs/" + page.key.slice(7) + ".md" : "/tree/main/docs");
    syntaxHighlight();
    outline(page);
    toggleMenu(false);
    const section = query && new URLSearchParams(query).get("section");
    if (section && document.getElementById(section)) {
      document.getElementById(section).scrollIntoView({ block: "start" });
    } else if (changed) {
      window.scrollTo({ top: 0, behavior: "instant" });
    }
  }

  function search() {
    const query = input.value.trim().toLowerCase();
    results.hidden = !query;
    navigation.hidden = Boolean(query);
    results.replaceChildren();
    if (!query) return;
    const terms = query.split(/\s+/);
    const matches = pages.map((page) => {
      const title = page.title.toLowerCase();
      const content = (page.title + " " + page.description + " " + page.search).toLowerCase();
      if (!terms.every((term) => content.includes(term))) return null;
      const score = (title === query ? 100 : title.includes(query) ? 40 : 0) + terms.filter((term) => title.includes(term)).length * 10;
      return { page, score };
    }).filter(Boolean).sort((a, b) => b.score - a.score);
    const summary = document.createElement("div");
    summary.className = "search-summary";
    summary.textContent = matches.length ? matches.length + " matching pages" : "No matching pages";
    results.append(summary);
    matches.slice(0, 30).forEach(({ page }) => {
      const link = document.createElement("a");
      link.className = "search-result";
      link.href = "#/" + page.key;
      const group = document.createElement("small");
      group.textContent = page.group;
      const title = document.createElement("strong");
      title.textContent = page.title;
      const description = document.createElement("span");
      description.textContent = page.description;
      link.append(group, title, description);
      link.addEventListener("click", () => { input.value = ""; search(); toggleMenu(false); });
      results.append(link);
    });
  }

  body.addEventListener("click", async (event) => {
    const button = event.target.closest(".copy-button");
    if (!button) return;
    const text = button.closest(".code-block").querySelector("pre code").textContent;
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(button.closest(".code-block").querySelector("pre code"));
        selection.removeAllRanges();
        selection.addRange(range);
        if (!document.execCommand("copy")) throw new Error("Copy unavailable");
        selection.removeAllRanges();
      }
      button.textContent = "Copied";
      notify("Code copied to clipboard");
      setTimeout(() => { button.textContent = "Copy"; }, 1600);
    } catch {
      notify("Select the code and copy it manually");
    }
  });
  input.addEventListener("input", search);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      const first = results.querySelector("a");
      if (first) first.click();
    } else if (event.key === "ArrowDown") {
      const first = results.querySelector("a");
      if (first) { event.preventDefault(); first.focus(); }
    }
  });
  results.addEventListener("keydown", (event) => {
    const links = [...results.querySelectorAll("a")];
    const index = links.indexOf(document.activeElement);
    if (event.key === "ArrowDown" && links[index + 1]) { event.preventDefault(); links[index + 1].focus(); }
    if (event.key === "ArrowUp") { event.preventDefault(); if (index > 0) links[index - 1].focus(); else input.focus(); }
  });
  menuButton.addEventListener("click", () => toggleMenu(!sidebar.classList.contains("open")));
  backdrop.addEventListener("click", () => toggleMenu(false));
  navigation.addEventListener("click", (event) => {
    if (event.target.closest("a")) toggleMenu(false);
  });
  document.querySelector(".skip-link").addEventListener("click", (event) => {
    event.preventDefault();
    article.focus();
    article.scrollIntoView({ block: "start" });
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { input.value = ""; search(); toggleMenu(false); }
    if (event.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) {
      event.preventDefault();
      if (window.matchMedia("(max-width: 850px)").matches) toggleMenu(true);
      input.focus();
    }
    if (event.key === "Tab" && sidebar.classList.contains("open")) {
      const focusable = [...sidebar.querySelectorAll("a, button, input")].filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    find("theme-button").setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }
  let savedTheme;
  try { savedTheme = localStorage.getItem("xnode-docs-theme"); } catch { /* Storage can be unavailable. */ }
  setTheme(savedTheme === "dark" || savedTheme === "light" ? savedTheme : (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  find("theme-button").addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(theme);
    try { localStorage.setItem("xnode-docs-theme", theme); } catch { /* Theme still applies for this visit. */ }
  });
  window.addEventListener("hashchange", render);
  window.addEventListener("resize", () => { if (!window.matchMedia("(max-width: 850px)").matches) toggleMenu(false); });
  render();
})();
