#!/usr/bin/env python3
import gi
import sys
import logging
import threading
import re
import datetime
from collections import defaultdict
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, Pango, GLib
import subprocess, os, grp, pwd, getpass
from logic import PolkitSystem, RuleGenerator

# Configuration
EXPECTED_HELPER_VERSION = "1.1"
EXPECTED_POLICY_VERSION = "1.1"
HELPER_PATH = "/usr/local/bin/polkit-editor-helper"
POLICY_PATH = "/usr/share/polkit-1/actions/org.example.polkit-editor.policy"

STYLE_DATA = b"""
@define-color accent #4a90d9;
@define-color surface #1e1e24;
@define-color surface-alt #242431;
@define-color text #e6e6f0;

window, dialog, box, paned, notebook, scrolledwindow {
    background: @surface;
    color: @text;
}

headerbar {
    background: linear-gradient(to right, shade(@accent, 1.35), @accent);
    color: white;
    box-shadow: 0 2px 6px rgba(0,0,0,0.4);
}

.dirty-action { background-color: #ff8c00; color: white; }
.namespace-btn { font-size: 0.95em; padding: 4px 8px; background: @surface-alt; color: @text; border-radius: 6px; }
.namespace-btn:hover { background: shade(@surface-alt, 1.2); }
.count-badge { color: @accent; font-size: 0.85em; font-weight: bold; margin-left: 6px; }
.audit-active { background-color: #e01b24; color: white; }
.status-warn { color: #ff8c00; font-weight: bold; }
.treeview { background: @surface-alt; }
"""

class AuditMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.process = None
        self.running = False

    def start(self):
        if self.running: return
        self.running = True
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None

    def _monitor_loop(self):
        print("[DEBUG] Audit Monitor: Started.")
        # Listen to all logs, filter in python
        cmd = ["journalctl", "-f", "-n", "50", "--output=short"]
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            while self.running:
                line = self.process.stdout.readline()
                if not line: break
                
                # We need to catch both polkit and dbus-daemon activations
                line_lower = line.lower()
                is_polkit = "polkit" in line_lower
                is_dbus = "dbus-daemon" in line_lower and "activating service" in line_lower
                
                if not (is_polkit or is_dbus): continue
                
                try:
                    full_line = line.strip()
                    timestamp = " ".join(full_line.split()[:3])
                    
                    action_id = "unknown"
                    user = "unknown"
                    result = "Info"

                    if is_polkit:
                        # Parse Polkit
                        act_match = re.search(r'(?:action|Action=)\s+([a-zA-Z0-9\.\-]+)', full_line)
                        if not act_match: continue
                        action_id = act_match.group(1)
                        if action_id == "org.freedesktop.policykit.exec": continue
                        
                        u_match = re.search(r'(?:unix-user:|user=)(\w+)', full_line)
                        if u_match: user = u_match.group(1)
                        
                        if "successfully" in line_lower or "accepted" in line_lower or "is authorized" in line_lower:
                            result = "Allowed"
                        elif "denied" in line_lower or "failed" in line_lower:
                            result = "Denied"
                            
                    elif is_dbus:
                        # Parse DBus
                        svc_match = re.search(r"name='([^']+)'", full_line)
                        if not svc_match: continue
                        action_id = svc_match.group(1)
                        
                        u_match = re.search(r'uid=(\d+)', full_line)
                        if u_match: 
                            try: user = pwd.getpwuid(int(u_match.group(1))).pw_name
                            except: user = u_match.group(1)
                        
                        result = "Activating" # DBus state

                    GLib.idle_add(self.callback, timestamp, action_id, user, result)
                except Exception as e:
                    print(f"[DEBUG] Audit Parse Error: {e}")
        except Exception as e:
            print(f"[DEBUG] Audit Monitor Error: {e}")
        print("[DEBUG] Audit Monitor: Stopped.")

class GroupEditorModal(Gtk.Dialog):
    def __init__(self, parent, action):
        super().__init__(title=f"Editing: {action.action_id}", transient_for=parent, modal=True)
        self.action = action
        self.user = getpass.getuser()
        self.set_default_size(850, 650)
        self.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("_Apply", Gtk.ResponseType.OK)
        
        box = self.get_content_area()
        box.set_spacing(10)
        for m in ["top", "bottom", "start", "end"]: getattr(box, f"set_margin_{m}")(15)
        
        h_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.member_store = Gtk.ListStore(str)
        for g in action.allowed_groups: self.member_store.append([f"👥 {g}"])
        self.member_tree = self.create_tree("Authorized Groups", self.member_store)
        self.member_tree.connect("row-activated", lambda t, p, c: self.move_item(self.member_tree, self.member_store, self.sys_store))
        
        self.sys_store = Gtk.ListStore(str)
        all_g = sorted([g.gr_name for g in grp.getgrall()])
        for g in all_g:
            if g not in action.allowed_groups: self.sys_store.append([f"👥 {g}"])
        self.sys_tree = self.create_tree("Available System Groups", self.sys_store)
        self.sys_tree.connect("row-activated", lambda t, p, c: self.move_item(self.sys_tree, self.sys_store, self.member_store))
        
        v_btns = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, valign=Gtk.Align.CENTER)
        b_add = Gtk.Button(label="◀ Add"); b_add.connect("clicked", lambda x: self.move_item(self.sys_tree, self.sys_store, self.member_store))
        b_rem = Gtk.Button(label="Rem ▶"); b_rem.connect("clicked", lambda x: self.move_item(self.member_tree, self.member_store, self.sys_store))
        v_btns.pack_start(b_add, False, False, 0); v_btns.pack_start(b_rem, False, False, 0)
        
        h_box.pack_start(self.scroll(self.member_tree), True, True, 0)
        h_box.pack_start(v_btns, False, False, 0)
        h_box.pack_start(self.scroll(self.sys_tree), True, True, 0)
        box.pack_start(h_box, True, True, 0)
        
        # User Section
        user_lbl_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        user_lbl_box.pack_start(Gtk.Label(label="<b>Authorized Specific Users:</b>", xalign=0, use_markup=True), True, True, 0)
        btn_add_me = Gtk.Button(label=f"Add Me ({self.user})")
        btn_add_me.connect("clicked", self.on_add_current_user)
        btn_rem_u = Gtk.Button(label="Remove Selected")
        btn_rem_u.connect("clicked", self.on_remove_user)
        user_lbl_box.pack_start(btn_add_me, False, False, 0)
        user_lbl_box.pack_start(btn_rem_u, False, False, 0)
        box.pack_start(user_lbl_box, False, False, 0)

        self.user_store = Gtk.ListStore(str)
        self.user_view = self.create_tree("User IDs", self.user_store)
        for u in action.allowed_users: self.user_store.append([f"👤 {u}"])
        box.pack_start(self.scroll(self.user_view), False, False, 0)

        f_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.combo = Gtk.ComboBoxText()
        self.combo.append("no", "Deny others"); self.combo.append("auth_admin", "Require Admin Password"); self.combo.append("yes", "Allow Access")
        self.combo.set_active_id(action.allow_any)
        f_box.pack_start(Gtk.Label(label="<b>Fallback Behavior:</b>", xalign=0, use_markup=True), False, False, 0)
        f_box.pack_start(self.combo, True, True, 0); box.pack_start(f_box, False, False, 5); self.show_all()

    def create_tree(self, t, s):
        tr = Gtk.TreeView(model=s); r = Gtk.CellRendererText(); tr.append_column(Gtk.TreeViewColumn(t, r, text=0)); return tr
    def scroll(self, w):
        s = Gtk.ScrolledWindow(); s.set_shadow_type(Gtk.ShadowType.IN); s.set_min_content_height(100); s.add(w); return s
    
    def move_item(self, st, ss, ds):
        m, i = st.get_selection().get_selected()
        if i: val = ss.get_value(i, 0); ds.append([val]); ss.remove(i)
        
    def on_add_current_user(self, btn):
        val = f"👤 {self.user}"
        if val not in [r[0] for r in self.user_store]: self.user_store.append([val])
        
    def on_remove_user(self, btn):
        m, i = self.user_view.get_selection().get_selected()
        if i: self.user_store.remove(i)

    def get_data(self):
        groups = [r[0].replace("👥 ", "") for r in self.member_store]
        users = [r[0].replace("👤 ", "") for r in self.user_store]
        return groups, users, self.combo.get_active_id()

class PolkitEditorApp(Gtk.Window):
    def __init__(self):
        print("[DEBUG] App initialization started...")
        super().__init__(title="Polkit Manager Pro")
        self.set_default_size(1400, 900)
        self.set_resizable(True)
        self.maximize()
        logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
        self.system = PolkitSystem(); self.is_elevated = False; self.user = getpass.getuser()
        self.filter_state = "all"
        self.audit_monitor = AuditMonitor(self.on_audit_event)
        
        provider = Gtk.CssProvider()
        try:
            provider.load_from_data(STYLE_DATA)
            Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        except Exception as e:
            print(f"[DEBUG] CSS Load Failed: {e}")

        self.setup_ui()
        print("[DEBUG] UI construction finished. Queuing data load...")
        GLib.idle_add(self.load_data, True) 
        
        # Check Versions & State
        GLib.idle_add(self.check_versions)
        if os.path.exists(self.system.persistent_priv_path): 
            print("[DEBUG] Persistent elevation detected.")
            self.elev_btn.set_active(True)

    def check_versions(self):
        mismatches = []
        # Check Helper
        try:
            if not os.path.exists(HELPER_PATH): mismatches.append("Helper Missing")
            else:
                with open(HELPER_PATH, 'r') as f:
                    content = f.read()
                    if f'VERSION = "{EXPECTED_HELPER_VERSION}"' not in content:
                        mismatches.append(f"Helper Version Mismatch (Expected {EXPECTED_HELPER_VERSION})")
        except: mismatches.append("Error Checking Helper")

        # Check Policy
        try:
            if not os.path.exists(POLICY_PATH): mismatches.append("Policy XML Missing")
            else:
                with open(POLICY_PATH, 'r') as f:
                    if f'VERSION: {EXPECTED_POLICY_VERSION}' not in f.read():
                        mismatches.append(f"Policy XML Version Mismatch (Expected {EXPECTED_POLICY_VERSION})")
        except: mismatches.append("Error Checking Policy")

        if mismatches:
            msg = " | ".join(mismatches)
            self.status.push(0, f"⚠️  System Integrity Warning: {msg}")
            context = self.status.get_style_context()
            context.add_class("status-warn")
        else:
            self.status.push(0, "System Integrity OK.")

    def setup_ui(self):
        main_v = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_v.set_vexpand(True); main_v.set_hexpand(True)
        self.add(main_v)
        
        hb = Gtk.HeaderBar(title="Polkit Policy Manager", show_close_button=True); self.set_titlebar(hb)
        
        self.elev_btn = Gtk.ToggleButton(label="Elevate"); self.elev_btn.connect("toggled", self.on_elevation_toggled); hb.pack_end(self.elev_btn)
        self.apply_btn = Gtk.Button(label="Apply Changes"); self.apply_btn.connect("clicked", self.on_save_clicked); hb.pack_start(self.apply_btn)
        
        self.audit_btn = Gtk.ToggleButton()
        self.audit_btn.set_image(Gtk.Image.new_from_icon_name("activity-start-symbolic", Gtk.IconSize.BUTTON))
        self.audit_btn.set_tooltip_text("Audit Mode: Watch for events")
        self.audit_btn.connect("toggled", self.on_audit_toggled)
        hb.pack_start(self.audit_btn)

        # Filter Box
        filter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        filter_box.set_margin_start(10); filter_box.set_margin_end(10); filter_box.set_margin_top(5); filter_box.set_margin_bottom(5)
        
        self.search = Gtk.SearchEntry(placeholder_text="Search actions, namespaces or descriptions...")
        self.search.connect("search-changed", lambda x: self.filter_model.refilter())
        filter_box.pack_start(self.search, True, True, 0)
        
        self.filter_stack = Gtk.Box(spacing=5)
        self.rb_all = Gtk.RadioButton.new_with_label(None, "All")
        self.rb_all.connect("toggled", self.on_filter_toggled, "all"); self.filter_stack.add(self.rb_all)
        rb_m = Gtk.RadioButton.new_with_label_from_widget(self.rb_all, "Managed")
        rb_m.connect("toggled", self.on_filter_toggled, "managed"); self.filter_stack.add(rb_m)
        rb_o = Gtk.RadioButton.new_with_label_from_widget(self.rb_all, "Overridden")
        rb_o.connect("toggled", self.on_filter_toggled, "overridden"); self.filter_stack.add(rb_o)
        
        filter_box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), False, False, 5)
        filter_box.pack_start(self.filter_stack, False, False, 0)
        main_v.pack_start(filter_box, False, False, 0)

        # Split Pane
        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.set_position(120); main_v.pack_start(paned, True, True, 0)

        # Top Pane: Namespaces
        ns_scroll = Gtk.ScrolledWindow(); ns_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.ns_box = Gtk.FlowBox(); self.ns_box.set_valign(Gtk.Align.START); self.ns_box.set_max_children_per_line(40)
        self.ns_box.set_selection_mode(Gtk.SelectionMode.NONE)
        ns_scroll.add(self.ns_box)
        paned.pack1(ns_scroll, resize=False, shrink=False)

        # Bottom Pane: Notebook
        notebook = Gtk.Notebook()
        
        # TAB 1
        self.store = Gtk.ListStore(str, int, str, str, str, str, bool, str, str)
        self.filter_model = self.store.filter_new(); self.filter_model.set_visible_func(self.filter_func)
        self.sort_model = Gtk.TreeModelSort(model=self.filter_model)
        self.tree = Gtk.TreeView(model=self.sort_model)
        self.tree.get_style_context().add_class("treeview")
        self.tree.connect("row-activated", self.on_row_activated); self.tree.connect("button-press-event", self.on_tree_right_click)
        self.tree.set_tooltip_column(7)
        ren_pix = Gtk.CellRendererPixbuf(); col_status = Gtk.TreeViewColumn("S", ren_pix)
        col_status.set_cell_data_func(ren_pix, self.status_cell_func); self.tree.append_column(col_status)
        cols = [("Action Identifier", 0), ("#", 1), ("Description", 2), ("Privileges", 3), ("Custom", 4), ("System Auth", 5)]
        for i, (t, idx) in enumerate(cols):
            ren = Gtk.CellRendererText(); c = Gtk.TreeViewColumn(t, ren); c.set_resizable(True); c.set_sort_column_id(idx)
            if idx in [0, 2]: c.set_expand(True)
            c.set_cell_data_func(ren, self.style_cell, idx); self.tree.append_column(c)
        sw_tree = Gtk.ScrolledWindow(); sw_tree.add(self.tree)
        notebook.append_page(sw_tree, Gtk.Label(label="Policy Rules"))

        # TAB 2
        self.log_store = Gtk.ListStore(str, str, str, str)
        self.log_tree = Gtk.TreeView(model=self.log_store)
        self.log_tree.connect("row-activated", self.on_log_row_activated)
        for i, t in enumerate(["Time", "Result", "User", "Action/Service"]):
            r = Gtk.CellRendererText(); c = Gtk.TreeViewColumn(t, r, text=i); c.set_resizable(True)
            if i == 1: c.set_cell_data_func(r, self.log_style_func)
            if i == 3: c.set_expand(True)
            self.log_tree.append_column(c)
        sw_log = Gtk.ScrolledWindow(); sw_log.add(self.log_tree)
        notebook.append_page(sw_log, Gtk.Label(label="Audit Log"))

        paned.pack2(notebook, resize=True, shrink=False)
        self.status = Gtk.Statusbar(); main_v.pack_end(self.status, False, False, 0)
        self.show_all()

    def on_audit_toggled(self, btn):
        if btn.get_active():
            self.audit_monitor.start()
            btn.get_style_context().add_class("audit-active")
            self.status.push(0, "Audit Mode: Monitoring system journal...")
        else:
            self.audit_monitor.stop()
            btn.get_style_context().remove_class("audit-active")
            self.status.push(0, "Audit Mode: Stopped.")

    def on_audit_event(self, timestamp, action_id, user, result):
        self.log_store.insert(0, [timestamp, result, user, action_id])
        if self.audit_btn.get_active() and "org.freedesktop" in action_id:
            self.search.set_text(action_id)
            self.filter_model.refilter()

    def on_log_row_activated(self, tree, path, col):
        m = tree.get_model(); iter = m.get_iter(path); aid = m.get_value(iter, 3)
        if aid in self.system.actions:
            d = GroupEditorModal(self, self.system.actions[aid])
            if d.run() == Gtk.ResponseType.OK:
                self.system.actions[aid].allowed_groups, self.system.actions[aid].allowed_users, self.system.actions[aid].allow_any = d.get_data()
                self.system.is_dirty = True; self.load_data(False)
            d.destroy()

    def log_style_func(self, col, cell, model, iter, data):
        val = model.get_value(iter, 1)
        if val == "Allowed": cell.set_property("foreground", "green"); cell.set_property("weight", Pango.Weight.BOLD)
        elif val == "Denied": cell.set_property("foreground", "red"); cell.set_property("weight", Pango.Weight.BOLD)
        elif val == "Activating": cell.set_property("foreground", "#d19a00"); cell.set_property("weight", Pango.Weight.NORMAL)
        else: cell.set_property("foreground", None); cell.set_property("weight", Pango.Weight.NORMAL)

    def create_ns_button(self, label, count):
        btn = Gtk.Button(); btn.get_style_context().add_class("namespace-btn")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        lbl_name = Gtk.Label(label=label)
        lbl_count = Gtk.Label(label=str(count)); lbl_count.get_style_context().add_class("count-badge")
        box.pack_start(lbl_name, True, True, 0); box.pack_start(lbl_count, False, False, 0)
        btn.add(box); btn.connect("clicked", self.on_ns_button_clicked, label); return btn

    def on_ns_button_clicked(self, btn, label):
        self.search.set_text("" if label == "All" else label); self.filter_model.refilter()

    def status_cell_func(self, col, cell, model, iter, data):
        try: cell.set_property("icon-name", str(model.get_value(iter, 8)) if model.get_value(iter, 8) else "")
        except: cell.set_property("icon-name", "")

    def on_filter_toggled(self, rb, key):
        if rb.get_active(): self.filter_state = key; self.filter_model.refilter()

    def filter_func(self, model, iter, data):
        try:
            aid = model.get_value(iter, 0); action = self.system.actions.get(aid)
            if not action: return False
            query = self.search.get_text().lower().strip()
            haystack = (aid + " " + action.description + " " + " ".join(action.allowed_groups) + " " + " ".join(action.allowed_users)).lower()
            if query and not all(term in haystack for term in query.split()): return False
            if self.filter_state == "managed": return action.is_managed()
            if self.filter_state == "overridden": return action.is_overridden()
            return True
        except: return False

    def style_cell(self, col, cell, model, iter, idx):
        try:
            aid = str(model.get_value(iter, 0)); is_ov = model.get_value(iter, 6)
            if idx == 0: cell.set_property("markup", f"<span color='#888'>{'.'.join(aid.split('.')[:-1])}.</span><b>{aid.split('.')[-1]}</b>")
            elif idx in [1, 2, 4, 5]: cell.set_property("text", str(model.get_value(iter, idx)))
            elif idx == 3:
                val = str(model.get_value(iter, 3)); cell.set_property("text", val)
                cell.set_property("foreground", "#cc0000" if "yes" in val.lower() else None)
                cell.set_property("weight", Pango.Weight.BOLD if "yes" in val.lower() else Pango.Weight.NORMAL)
            if is_ov and idx != 3: cell.set_property("foreground", "gray"); cell.set_property("font-desc", Pango.FontDescription("italic"))
            elif idx != 3: cell.set_property("foreground", None); cell.set_property("font-desc", None)
        except: pass

    def load_data(self, sync_disk=False):
        if sync_disk: self.system.refresh()
        self.store.clear(); ns_counts = defaultdict(int)
        for aid, a in self.system.actions.items():
            ns_counts[a.get_namespace()] += 1
            prec = 90 if a.is_managed() else (a.effective_rule.precedence if a.effective_rule else 0)
            status_icon = "dialog-warning-symbolic" if a.is_overridden() else ("emblem-system-symbolic" if a.is_managed() else "")
            privs = f"Any:{a.defaults.get('allow_any','?')}, Active:{a.defaults.get('allow_active','?')}"
            custom = ", ".join([f"👤{u}" for u in a.allowed_users] + [f"👥{g}" for g in a.allowed_groups])
            ext = ", ".join([f"👤{u}" for u in a.external_users.keys()] + [f"👥{g}" for g in a.external_groups.keys()])
            tt = f"Action: {aid}\nActive Rule: {a.effective_rule.filename if a.effective_rule else 'None'}"
            self.store.append([aid, prec, a.description, privs, custom or "-", ext or "-", a.is_overridden(), tt, status_icon])
        
        for c in self.ns_box.get_children(): self.ns_box.remove(c)
        total = sum(ns_counts.values())
        self.ns_box.add(self.create_ns_button("All", total))
        for ns, count in sorted(ns_counts.items(), key=lambda item: item[1], reverse=True): self.ns_box.add(self.create_ns_button(ns, count))
        self.ns_box.show_all(); self.update_ui_state();
        self.status.push(0, f"Loaded {total} actions • Managed: {len([a for a in self.system.actions.values() if a.is_managed()])}")
        self.queue_draw()

    def update_ui_state(self):
        title = "Polkit Manager Pro" + (" [Elevated]" if self.is_elevated else "") + (" * UNSAVED *" if self.system.is_dirty else "")
        if self.system.is_dirty: self.apply_btn.get_style_context().add_class("dirty-action")
        else: self.apply_btn.get_style_context().remove_class("dirty-action")
        self.set_title(title)

    def on_row_activated(self, tree, path, col):
        m = tree.get_model(); aid = m.get_value(m.get_iter(path), 0); action = self.system.actions[aid]
        d = GroupEditorModal(self, action)
        if d.run() == Gtk.ResponseType.OK:
            action.allowed_groups, action.allowed_users, action.allow_any = d.get_data()
            self.system.is_dirty = True; self.load_data(False)
        d.destroy()

    def on_tree_right_click(self, tree, event):
        if event.button == 3:
            path_info = tree.get_path_at_pos(int(event.x), int(event.y))
            if path_info:
                path, col, x, y = path_info; m = tree.get_model(); iter = m.get_iter(path); aid = m.get_value(iter, 0)
                menu = Gtk.Menu()
                m0 = Gtk.MenuItem(label=f"Quick Authorize ({self.user})"); m0.connect("activate", lambda x: self.add_user_to_action(aid)); menu.append(m0)
                m1 = Gtk.MenuItem(label="Open Policy XML"); m1.connect("activate", lambda x: self.open_path(self.system.actions[aid].origin_file)); menu.append(m1)
                menu.show_all(); menu.popup(None, None, None, None, event.button, event.time); return True

    def add_user_to_action(self, aid):
        action = self.system.actions[aid]
        if self.user not in action.allowed_users: action.allowed_users.append(self.user); self.system.is_dirty = True; self.load_data(False)

    def on_save_clicked(self, b):
        if not self.is_elevated: self.show_error("Elevate first."); return
        js = RuleGenerator.generate(self.system.actions); tmp = "/tmp/pk_out.rules"
        try:
            with open(tmp, "w", encoding='utf-8') as f: f.write(js)
            subprocess.run(["pkexec", "/usr/local/bin/polkit-editor-helper", "write", tmp], check=True)
            self.load_data(sync_disk=True)
        except Exception as e: self.show_error(str(e))

    def on_elevation_toggled(self, b): self.is_elevated = b.get_active(); self.update_ui_state()

    def open_path(self, path):
        if not path or not os.path.exists(path): return
        uri = GLib.filename_to_uri(os.path.abspath(path), None)
        Gtk.show_uri_on_window(self, uri, Gdk.CURRENT_TIME)

    def on_restart_polkit(self, b):
        if not self.is_elevated: self.show_error("Elevate first."); return
        subprocess.run(["pkexec", "systemctl", "restart", "polkit"])

    def toggle_forever(self, widget):
        path = self.system.persistent_priv_path
        if os.path.exists(path): subprocess.run(["pkexec", "rm", path]); self.status.push(0, "Forever off.")
        else:
            js = f'polkit.addRule(function(action, subject) {{ if (action.id == "org.example.polkit-editor.write" && subject.user == "{self.user}") return polkit.Result.YES; }});'
            open("/tmp/pk_priv.rules", "w").write(js); subprocess.run(["pkexec", "cp", "/tmp/pk_priv.rules", path]); self.status.push(0, "Forever on.")

    def show_help(self, b):
        d = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK, text="Polkit Manager Help")
        d.format_secondary_text("Legend:\n⚙ = Managed Action\n⚠ = Overridden\n👤 = User | 👥 = Group"); d.run(); d.destroy()

    def show_error(self, m):
        d = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK, text=m); d.run(); d.destroy()

def main():
    app = PolkitEditorApp()
    app.connect("destroy", Gtk.main_quit)
    Gtk.main()


if __name__ == "__main__":
    main()
