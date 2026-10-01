import { CustomEditor } from "@earendil-works/pi-coding-agent";

export default function (pi) {
  pi.on("session_start", (_event, ctx) => {
    if (ctx.mode !== "tui") return;

    ctx.ui.addAutocompleteProvider((provider) => ({
      triggerCharacters: provider.triggerCharacters,
      async getSuggestions(...args) {
        const suggestions = await provider.getSuggestions(...args);
        if (!suggestions?.prefix.startsWith("/")) return suggestions;
        const items = suggestions.items.filter((item) => item.value !== "login");
        return items.length ? { ...suggestions, items } : null;
      },
      applyCompletion: (...args) => provider.applyCompletion(...args),
      shouldTriggerFileCompletion: (...args) => provider.shouldTriggerFileCompletion?.(...args) ?? false,
    }));

    let editor;
    const previous = ctx.ui.getEditorComponent();
    ctx.ui.setEditorComponent((...args) => {
      editor = previous?.(...args) ?? new CustomEditor(...args);
      return editor;
    });
    const submit = editor.onSubmit;
    editor.onSubmit = (text) => {
      if (/^\/login(?:\s|$)/.test(text.trim())) {
        ctx.ui.notify("Do not enter keys in sandbox Pi. Run pi-windows-sandbox login <provider> on the host.", "warning");
        return;
      }
      return submit?.(text);
    };
  });
}
