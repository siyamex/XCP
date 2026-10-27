export type Theme = "light" | "dark" | "system";

const KEY = "xcp-theme";

export function getTheme(): Theme {
  try {
    const t = localStorage.getItem(KEY);
    if (t === "light" || t === "dark") return t;
  } catch {
    // storage blocked: fall back to the system setting
  }
  return "system";
}

export function applyTheme(theme: Theme = getTheme()) {
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}

export function setTheme(theme: Theme) {
  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    // ignore: the choice just won't persist
  }
  applyTheme(theme);
}
