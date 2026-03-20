import tkinter as tk
from tkinter import messagebox
import threading
from cert_checker import get_certificate, parse_cert


COLORS = {
    'bg':              '#0f1923',
    'panel':           '#1a2535',
    'btn':             '#00e5ff',
    'btn_text':        '#0f1923',
    'accent':          '#00e5ff',
    'VALID':           '#00cc66',
    'EXPIRED':         '#ff3355',
    'HOSTNAME MISMATCH': '#ff3355',
    'EXPIRING SOON':   '#ffaa00',
    'text':            '#c8dce8',
    'dim':             '#4a6070',
}


def create_app():
    root = tk.Tk()
    root.title("SSL/TLS Certificate Verifier")
    root.geometry("680x580")
    root.configure(bg=COLORS['bg'])
    root.resizable(False, False)

    # ── Title ──────────────────────────────────────────
    tk.Label(root,
             text="SSL/TLS Certificate Verifier",
             font=("Courier", 16, "bold"),
             bg=COLORS['bg'], fg=COLORS['accent']
             ).pack(pady=(20, 2))

    tk.Label(root,
             text="Cybersecurity Project  —  Certificate Analysis Tool",
             font=("Courier", 9),
             bg=COLORS['bg'], fg=COLORS['dim']
             ).pack()

    # ── Input area ─────────────────────────────────────
    frame_input = tk.Frame(root, bg=COLORS['panel'], pady=14, padx=20)
    frame_input.pack(fill='x', padx=20, pady=14)

    tk.Label(frame_input,
             text="Enter domain name:",
             font=("Courier", 9),
             bg=COLORS['panel'], fg=COLORS['dim']
             ).pack(anchor='w')

    row = tk.Frame(frame_input, bg=COLORS['panel'])
    row.pack(fill='x', pady=(6, 0))

    url_var = tk.StringVar()
    entry = tk.Entry(row, textvariable=url_var,
                     font=("Courier", 12),
                     bg='#0f1923', fg=COLORS['accent'],
                     insertbackground=COLORS['accent'],
                     relief='flat', bd=6)
    entry.pack(side='left', fill='x', expand=True)
    entry.insert(0, "e.g. google.com")
    entry.bind("<FocusIn>",  lambda e: entry.delete(0, 'end')
               if entry.get().startswith("e.g") else None)

    btn = tk.Button(row,
                    text="  Verify  ",
                    font=("Courier", 10, "bold"),
                    bg=COLORS['btn'], fg=COLORS['btn_text'],
                    relief='flat', padx=10, cursor='hand2',
                    command=lambda: run_verify(url_var.get()))
    btn.pack(side='right', padx=(10, 0))

    root.bind('<Return>', lambda e: run_verify(url_var.get()))

    # ── Status banner ──────────────────────────────────
    status_var = tk.StringVar(value="Enter a domain above and click Verify")
    status_lbl = tk.Label(root, textvariable=status_var,
                          font=("Courier", 13, "bold"),
                          bg=COLORS['bg'], fg=COLORS['dim'])
    status_lbl.pack(pady=(4, 0))

    # ── Results panel ──────────────────────────────────
    frame_res = tk.Frame(root, bg=COLORS['panel'], padx=24, pady=16)
    frame_res.pack(fill='both', expand=True, padx=20, pady=(8, 10))

    fields = [
        ("Common Name (CN)",  'cn'),
        ("Organization",      'org'),
        ("Issuer",            'issuer_cn'),
        ("Issuer Org",        'issuer_org'),
        ("Valid From",        'not_before'),
        ("Valid Until",       'not_after'),
        ("Days Remaining",    'days_left'),
        ("Hostname Match",    'host_match'),
        ("Total SANs",        'sans_count'),
    ]

    result_vars = {}
    result_lbls = {}

    for i, (label, key) in enumerate(fields):
        tk.Label(frame_res,
                 text=label + ":",
                 width=22, anchor='w',
                 font=("Courier", 9),
                 bg=COLORS['panel'], fg=COLORS['dim']
                 ).grid(row=i, column=0, sticky='w', pady=3)

        var = tk.StringVar(value="—")
        result_vars[key] = var
        lbl = tk.Label(frame_res,
                       textvariable=var,
                       anchor='w',
                       font=("Courier", 10, "bold"),
                       bg=COLORS['panel'], fg=COLORS['text'])
        lbl.grid(row=i, column=1, sticky='w', padx=12)
        result_lbls[key] = lbl

    # SANs text box
    tk.Label(frame_res,
             text="Subject Alt Names:",
             width=22, anchor='nw',
             font=("Courier", 9),
             bg=COLORS['panel'], fg=COLORS['dim']
             ).grid(row=len(fields), column=0, sticky='nw', pady=3)

    sans_box = tk.Text(frame_res,
                       height=4, width=46,
                       font=("Courier", 8),
                       bg='#0f1923', fg=COLORS['accent'],
                       relief='flat', state='disabled')
    sans_box.grid(row=len(fields), column=1, sticky='w', padx=12, pady=3)

    # ── Core logic ─────────────────────────────────────
    def run_verify(raw):
        host = raw.strip().replace("https://", "").replace("http://", "").rstrip("/")
        if not host or host.startswith("e.g"):
            messagebox.showwarning("Missing input", "Please type a domain name first.")
            return

        btn.config(state='disabled', text=" Checking... ")
        status_var.set(f"Connecting to  {host} ...")
        status_lbl.config(fg=COLORS['dim'])
        for v in result_vars.values():
            v.set("—")
        sans_box.config(state='normal')
        sans_box.delete('1.0', 'end')
        sans_box.config(state='disabled')

        def fetch():
            try:
                cert = get_certificate(host)
                info = parse_cert(cert, host)
                root.after(0, lambda: show_results(info))
            except Exception as ex:
                root.after(0, lambda: show_error(str(ex)))

        threading.Thread(target=fetch, daemon=True).start()

    def show_results(info):
        status  = info['status']
        color   = COLORS.get(status, COLORS['text'])
        icons   = {'VALID': '✅', 'EXPIRED': '❌',
                   'HOSTNAME MISMATCH': '❌', 'EXPIRING SOON': '⚠️'}
        icon    = icons.get(status, 'ℹ️')

        status_var.set(f"{icon}  {status}")
        status_lbl.config(fg=color)

        days_str = "EXPIRED" if info['is_expired'] else f"{info['days_left']} days"
        host_str = "✅  Yes"  if info['host_match'] else "❌  No"

        values = {
            'cn':         info['cn'],
            'org':        info['org'] or 'N/A',
            'issuer_cn':  info['issuer_cn'],
            'issuer_org': info['issuer_org'] or 'N/A',
            'not_before': info['not_before'],
            'not_after':  info['not_after'],
            'days_left':  days_str,
            'host_match': host_str,
            'sans_count': str(len(info['sans'])),
        }

        for key, val in values.items():
            result_vars[key].set(val)

        # colour-code specific rows
        result_lbls['days_left'].config(fg=color)
        result_lbls['host_match'].config(
            fg=COLORS['VALID'] if info['host_match'] else COLORS['EXPIRED'])

        sans_box.config(state='normal')
        sans_box.delete('1.0', 'end')
        sans_box.insert('end', "\n".join(info['sans'][:12]))
        sans_box.config(state='disabled')

        btn.config(state='normal', text="  Verify  ")

    def show_error(msg):
        status_var.set("❌  Could not connect")
        status_lbl.config(fg=COLORS['EXPIRED'])
        messagebox.showerror("Connection Error",
                             f"Failed to verify certificate:\n\n{msg}")
        btn.config(state='normal', text="  Verify  ")

    root.mainloop()


create_app()