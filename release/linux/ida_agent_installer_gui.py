"""Graphical setup window, using the distribution's Tk instead of IDA's Qt."""
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import ida_agent_installer as installer


ZH = {
    "IDA Agent Setup": "IDA Agent 安装设置",
    "AI Chat and MCP for IDA Professional 9.4": "IDA Professional 9.4 的 AI Chat 与 MCP",
    "IDA user directory": "IDA 用户目录",
    "Browse…": "浏览…",
    "Install plugin": "安装插件",
    "Open manager": "打开管理页",
    "Remove plugin": "移除插件",
    "Ready to install the plugin for this user.": "可以为当前用户安装 IDA 插件。",
    "Plugin installed. Package upgrades update this link automatically.": "插件已安装。升级安装包时会自动更新此链接。",
    "An existing plugin was found. Installation can keep a backup before replacing it.": "检测到已有插件。安装时可先保留备份，再替换。",
    "Close IDA and IDAT before installing or removing the plugin.": "安装或移除插件前，请先关闭 IDA 和 IDAT。",
    "The manager opens in your browser and configures external MCP clients.": "管理页在浏览器中打开，用于配置外部 MCP 客户端。",
    "Back up existing plugin?": "是否备份已有插件？",
    "Keep a backup of the existing plugin and install the packaged version?": "保留已有插件的备份，并安装软件包中的版本？",
    "Plugin installed. Start IDA and open a database to use AI Chat.": "插件已安装。启动 IDA 并打开数据库，即可使用 AI Chat。",
    "Remove the managed plugin link from this IDA user directory?": "从此 IDA 用户目录移除安装包管理的插件链接？",
    "Plugin removed. Your settings and chat history are preserved.": "插件已移除。设置和聊天历史已保留。",
    "Opening manager…": "正在打开管理页…",
    "IDA Agent error": "IDA Agent 错误",
    "Select the IDA user directory": "选择 IDA 用户目录",
}


class InstallerWindow:
    def __init__(self, root, payload, user_directory):
        self.root, self.payload = root, payload
        language = os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES") or os.environ.get("LANG", "")
        self.translate = lambda text: ZH.get(text, text) if language.startswith("zh") else text
        self.events = queue.Queue()
        self.closed = False
        self.timer = None
        root.bind("<Destroy>", self.on_destroy, add="+")
        self.directory = tk.StringVar(value=str(user_directory))
        self.status = tk.StringVar()
        root.title(self.translate("IDA Agent Setup"))
        root.minsize(650, 390)
        root.geometry("710x410")
        root.configure(background="#f4f6f8")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f4f6f8")
        style.configure("TLabel", background="#f4f6f8", foreground="#243442")
        style.configure("Title.TLabel", font=("sans-serif", 22, "bold"))
        style.configure("Muted.TLabel", foreground="#586875")
        style.configure("TButton", padding=(12, 9))
        style.configure("Accent.TButton", background="#ff9720", foreground="#0c1922")
        style.map("Accent.TButton", background=[("active", "#ffad4a")])
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 22))
        icon = tk.Canvas(header, width=68, height=68, background="#f4f6f8", highlightthickness=0)
        icon.pack(side="left", padx=(0, 16))
        icon.create_oval(4, 4, 64, 64, fill="#0c1922", outline="#ff9720", width=2)
        icon.create_line(18, 48, 18, 20, 34, 38, 50, 20, 50, 48,
                         fill="#ff9720", width=6, capstyle="round", joinstyle="round")
        for x, y in ((18, 20), (34, 38), (50, 20)):
            icon.create_oval(x - 5, y - 5, x + 5, y + 5, fill="#41e2eb", outline="")
        try:
            self.icon = tk.PhotoImage(file=str(payload / "ida-agent.png"))
            root.iconphoto(True, self.icon)
        except tk.TclError:
            pass
        title = ttk.Frame(header)
        title.pack(side="left", fill="x", expand=True)
        ttk.Label(title, text="IDA Agent", style="Title.TLabel").pack(anchor="w")
        ttk.Label(title, text=self.translate("AI Chat and MCP for IDA Professional 9.4"),
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        version = (payload / "VERSION").read_text(encoding="ascii").strip()
        ttk.Label(header, text=f"{version}\nUbuntu / Debian", style="Muted.TLabel",
                  justify="right").pack(side="right", anchor="n")
        ttk.Label(frame, text=self.translate("IDA user directory")).grid(row=1, column=0, sticky="w")
        paths = ttk.Frame(frame)
        paths.grid(row=2, column=0, sticky="ew", pady=(7, 16))
        paths.columnconfigure(0, weight=1)
        ttk.Entry(paths, textvariable=self.directory).grid(row=0, column=0, sticky="ew", padx=(0, 10))
        ttk.Button(paths, text=self.translate("Browse…"), command=self.browse).grid(row=0, column=1)
        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, sticky="w", pady=(0, 18))
        ttk.Button(buttons, text=self.translate("Install plugin"), style="Accent.TButton",
                   command=self.install).pack(side="left", padx=(0, 10))
        self.manager_button = ttk.Button(buttons, text=self.translate("Open manager"), command=self.manager)
        self.manager_button.pack(side="left", padx=(0, 10))
        ttk.Button(buttons, text=self.translate("Remove plugin"), command=self.remove).pack(side="left")
        ttk.Label(frame, textvariable=self.status, wraplength=655).grid(row=4, column=0, sticky="w")
        ttk.Separator(frame).grid(row=5, column=0, sticky="ew", pady=(20, 12))
        ttk.Label(frame, text=self.translate("Close IDA and IDAT before installing or removing the plugin."),
                  style="Muted.TLabel", wraplength=655).grid(row=6, column=0, sticky="w")
        ttk.Label(frame, text=self.translate("The manager opens in your browser and configures external MCP clients."),
                  style="Muted.TLabel", wraplength=655).grid(row=7, column=0, sticky="w", pady=(5, 0))
        self.directory.trace_add("write", lambda *_: self.refresh())
        self.refresh()
        root.update_idletasks()
        width, height = max(710, root.winfo_reqwidth()), max(410, root.winfo_reqheight())
        root.minsize(width, height)
        root.geometry(f"{width}x{height}")
        self.timer = root.after(100, self.poll_events)

    def refresh(self):
        status = installer.plugin_status(self.payload, self.directory.get())
        text = {"installed": "Plugin installed. Package upgrades update this link automatically.",
                "conflict": "An existing plugin was found. Installation can keep a backup before replacing it.",
                "missing": "Ready to install the plugin for this user."}[status]
        self.status.set(self.translate(text))

    def browse(self):
        selected = filedialog.askdirectory(parent=self.root, title=self.translate("Select the IDA user directory"),
                                           initialdir=self.directory.get(), mustexist=False)
        if selected:
            self.directory.set(selected)

    def install(self):
        try:
            installer.require_ida_closed()
            replace = installer.plugin_status(self.payload, self.directory.get()) == "conflict"
            if replace and not messagebox.askyesno(self.translate("Back up existing plugin?"),
                    self.translate("Keep a backup of the existing plugin and install the packaged version?"),
                    parent=self.root):
                return
            _, backup = installer.install_plugin(self.payload, self.directory.get(), replace=replace)
            self.status.set(self.translate("Plugin installed. Start IDA and open a database to use AI Chat.")
                            + (f"\nBackup: {backup}" if backup else ""))
        except (OSError, RuntimeError) as error:
            messagebox.showerror(self.translate("IDA Agent error"), str(error), parent=self.root)

    def remove(self):
        if not messagebox.askyesno("IDA Agent", self.translate(
                "Remove the managed plugin link from this IDA user directory?"), parent=self.root):
            return
        try:
            installer.require_ida_closed()
            installer.remove_plugin(self.payload, self.directory.get())
            self.status.set(self.translate("Plugin removed. Your settings and chat history are preserved."))
        except (OSError, RuntimeError) as error:
            messagebox.showerror(self.translate("IDA Agent error"), str(error), parent=self.root)

    def manager(self):
        self.manager_button.configure(state="disabled")
        self.status.set(self.translate("Opening manager…"))
        def start():
            try:
                self.events.put((installer.open_manager(self.payload), None))
            except (OSError, RuntimeError) as error:
                self.events.put((None, str(error)))
        threading.Thread(target=start).start()

    def on_destroy(self, event):
        if event.widget == self.root:
            self.closed = True
            if self.timer is not None:
                try:
                    self.root.after_cancel(self.timer)
                except tk.TclError:
                    pass

    def poll_events(self):
        if self.closed:
            return
        try:
            url, error = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.manager_button.configure(state="normal")
            if error:
                messagebox.showerror(self.translate("IDA Agent error"), error, parent=self.root)
                self.refresh()
            else:
                self.status.set(url)
        self.timer = self.root.after(100, self.poll_events)


def show_installer(payload, user_directory):
    root = tk.Tk(className="Idaagent")
    InstallerWindow(root, payload, user_directory)
    root.mainloop()
