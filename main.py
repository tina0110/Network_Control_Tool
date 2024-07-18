import os
import sqlite3
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import threading
import time
import tkinter.font as tkFont
import sqlite3


# Get the path to the user's Documents directory
documents_path = os.path.join(os.path.expanduser("~"), "Documents")
ipdb_path = os.path.join(documents_path, "ipdb")

# Create the ipdb folder if it doesn't exist
if not os.path.exists(ipdb_path):
    os.makedirs(ipdb_path)

# Set the database path to the ipdb folder
db_path = os.path.join(ipdb_path, 'ip_address.db')

# interval.py
interval_db_path = db_path

def create_interval_table():
    try:
        with sqlite3.connect(interval_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS interval_table (
                    id INTEGER PRIMARY KEY,
                    interval_value INTEGER
                )
            ''')
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating interval_table: {e}")

def set_interval_value(value):
    try:
        with sqlite3.connect(interval_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO interval_table (interval_value) VALUES (?)", (value,))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error setting interval value: {e}")

def get_interval_value():
    try:
        with sqlite3.connect(interval_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT interval_value FROM interval_table ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return row[0]
            else:
                return None
    except sqlite3.Error as e:
        print(f"Error fetching interval value: {e}")

def update_interval_value(new_value):
    try:
        with sqlite3.connect(interval_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE interval_table SET interval_value=?", (new_value,))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error updating interval value: {e}")

def delete_interval_value():
    try:
        with sqlite3.connect(interval_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM interval_table")
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error deleting interval value: {e}")


# Global variables 
terminate_ping = False
status_label = None  

# Run diagnostics function
def run_diagnostics():
    interval = get_interval_value() or 60  
    start_pinging(interval)

# Function to ping IPs
def ping_ips(interval, update_callback):
    global terminate_ping
    while not terminate_ping:
        output_lines = []
        disconnected_ips = []
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, ip, priority, location, remarks FROM ip_address ORDER BY Priority ASC")
                rows = cursor.fetchall()
                 #dictionary 
                ip_details = {row[1]: row for row in rows} 
        except sqlite3.Error as e:
            update_callback(f"Error fetching IP addresses: {e}")
            return
        
        for ip in ip_details:
            try:
                result = os.popen(f"ping {ip}").read()

                if ("Request timed out" in result or "could not find host" in result or "100% packet loss" in result or "Destination host unreachable" in result ):
                    details = ip_details[ip]
                    disconnected_ips.append(f"ID: {details[0]}\nIP: {details[1]}\nPriority: {details[2]}\nLocation: {details[3]}\nRemarks: {details[4]}\n")
                    print(result)
                else:
                    output_lines.append(f"{ip} - Connected\n")
                    print(result)

            except Exception as e:
                output_lines.append(f"Error occurred while pinging {ip}: {e}\n")

        if disconnected_ips:
            update_callback("".join(disconnected_ips))
            messagebox.showinfo("Disconnected IPs", "\n\n".join(disconnected_ips), icon='warning')  # Custom dimensions and icon
        else:
            update_callback("All IPs are connected.")

        time.sleep(interval)

    # Show message box when pinging function is terminated
    messagebox.showinfo("Pinging Terminated", "Pinging has been terminated.")

# Function to start the pinging process in a new thread
def start_pinging(interval):
    global terminate_ping

    def update_callback(output_lines):
        root.after(0, show_results, output_lines)

    # Reset terminate_ping flag
    terminate_ping = False

    # Update status label in GUI to show "Running..."
    status_label.config(text="Running...")

    ping_thread = threading.Thread(target=ping_ips, args=(interval, update_callback), daemon=True)
    ping_thread.start()

# Function to terminate the pinging process
def terminate_diagnostics():
    global terminate_ping
    terminate_ping = True
    # Update status label in GUI to show "Terminating..."
    status_label.config(text="")

# Function to show results in a new window
def show_results(output_lines):
    pass

# Function to open a new window for adding IPs
def add_ip():

    if not os.path.exists(ipdb_path):
        os.makedirs(ipdb_path)

    add_ip_window = create_new_window("Add IP Addresses", "500x700")

    ip_list = []

    def add_ip_to_list():
        id = id_entry.get().strip()
        ip = ip_entry.get().strip()
        priority = priority_entry.get().strip()
        location = location_entry.get().strip()
        remarks = remarks_entry.get().strip()

        if ip and priority and location and id:
            ip_list.append((id, ip, priority, location, remarks))
            ip_listbox.insert(tk.END, f"ID: {id}, IP: {ip}, Priority: {priority}, Location: {location}, Remarks: {remarks}")
            id_entry.delete(0,tk.END)
            ip_entry.delete(0, tk.END)
            priority_entry.delete(0, tk.END)
            location_entry.delete(0, tk.END)
            remarks_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "All fields (ID ,IP Address, Priority, Location) are required.")

    def save_ips():
        if ip_list:
            try:
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS ip_address (
                            id INTEGER PRIMARY KEY,
                            ip TEXT,
                            priority INTEGER,
                            location TEXT,
                            remarks TEXT
                        )
                    ''')
                    for ip_info in ip_list:
                        cursor.execute("INSERT INTO ip_address (id ,ip, priority, location, remarks) VALUES (?,?, ?, ?, ?)", ip_info)
                    conn.commit()
                messagebox.showinfo("Success", "IP addresses saved successfully.")
                add_ip_window.destroy()
            except sqlite3.Error as e:
                messagebox.showerror("Error saving IP addresses: {e}")
        else:
            messagebox.showwarning("Warning", "Please add at least one IP address.")


    

    ip_label = tk.Label(add_ip_window, text="Add IP's from here:- ", font=('Segoe UI', 12), fg='black', bg='#cce7ff')
    ip_label.pack(pady=5)

    priority_label = tk.Label(add_ip_window, text="Enter ID:")
    priority_label.pack(pady=5)

    id_entry = tk.Entry(add_ip_window)
    id_entry.pack(pady=5)

    priority_label = tk.Label(add_ip_window, text="Enter IP Address:")
    priority_label.pack(pady=5)

    ip_entry = tk.Entry(add_ip_window)
    ip_entry.pack(pady=5)

    priority_label = tk.Label(add_ip_window, text="Enter Priority:")
    priority_label.pack(pady=5)

    priority_entry = tk.Entry(add_ip_window)
    priority_entry.pack(pady=5)

    location_label = tk.Label(add_ip_window, text="Enter Location:")
    location_label.pack(pady=5)

    location_entry = tk.Entry(add_ip_window)
    location_entry.pack(pady=5)

    remarks_label = tk.Label(add_ip_window, text="Enter Remarks:")
    remarks_label.pack(pady=5)

    remarks_entry = tk.Entry(add_ip_window)
    remarks_entry.pack(pady=5)

    add_button = ttk.Button(add_ip_window, text="Add IP Address", command=add_ip_to_list)
    add_button.pack(pady=10)

    ip_listbox = tk.Listbox(add_ip_window)
    ip_listbox.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    save_button = ttk.Button(add_ip_window, text="Save", command=save_ips)
    save_button.pack(pady=10)

# Function to modify IPs
def modify():
    modify_window = create_new_window("Modify IP Addresses", "1000x600")

    def refresh_ip_list():
        ip_tree.delete(*ip_tree.get_children())
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, ip, priority, location, remarks FROM ip_address ORDER BY priority ASC")
                rows = cursor.fetchall()
                for index, row in enumerate(rows, start=1):
                    ip_tree.insert("", tk.END, values=(index, row[0],row[1], row[2], row[3], row[4]))
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Error fetching IP addresses: {e}")

    def delete_ip():
        selected_item = ip_tree.selection()
        if selected_item:
            ip_id = ip_tree.item(selected_item)['values'][1]  # assuming id is the first column
            try:
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM ip_address WHERE id=?", (ip_id,))
                    conn.commit()
                    refresh_ip_list()
                    messagebox.showinfo("Success", "IP address deleted successfully.")
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Error deleting IP address: {e}")
        else:
            messagebox.showwarning("Warning", "Please select an IP address to delete.")

    def edit_ip():
        selected_item = ip_tree.selection()
        if selected_item:
            ip_id = ip_tree.item(selected_item)['values'][1]  # assuming id is the first column
            try:
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id ,ip, priority, location, remarks FROM ip_address WHERE id=?", (ip_id,))
                    row = cursor.fetchone()
                    if row:
                        current_id = row[0]
                        current_ip = row[1]
                        current_priority = row[2]
                        current_location = row[3]
                        current_remarks = row[4]

                        # Prompt user for new values
                        new_id = simpledialog.askinteger("Edit IP Address ID", "Enter new IP address ID:", initialvalue=current_id)
                        new_ip = simpledialog.askstring("Edit IP Address", "Enter new IP address:", initialvalue=current_ip)
                        new_priority = simpledialog.askstring("Edit Priority", "Enter new Priority:", initialvalue=current_priority)
                        new_location = simpledialog.askstring("Edit Location", "Enter new Location:", initialvalue=current_location)
                        new_remarks = simpledialog.askstring("Edit Remarks", "Enter new Remarks:", initialvalue=current_remarks)

                        if new_ip or new_priority or new_location or new_remarks or new_id:
                            # Update the database with new values
                            cursor.execute("UPDATE ip_address SET id=?, ip=?, priority=?, location=?, remarks=? WHERE id=?",
                                           (new_id, new_ip, new_priority, new_location, new_remarks, ip_id))
                            conn.commit()
                            refresh_ip_list()
                            messagebox.showinfo("Success", "IP address updated successfully.")
                    else:
                        messagebox.showwarning("Warning", "IP address not found.")
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Error updating IP address: {e}")
        else:
            messagebox.showwarning("Warning", "Please select an IP address to edit.")

    def search_ip():
        search_value = search_entry.get().strip()
        if search_value :
            try:
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    # Search by IP or ID (assuming search_value can be either)
                    cursor.execute("SELECT id, ip, priority, location, remarks FROM ip_address WHERE ip=? OR id=? OR location=? ORDER BY priority ASC",
                                   (search_value, search_value, search_value))
                    rows = cursor.fetchall()
                    ip_tree.delete(*ip_tree.get_children())
                    for index, row in enumerate(rows, start=1):
                        ip_tree.insert("", tk.END, values=(index, row[0],row[1], row[2], row[3], row[4]))
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Error searching IP addresses: {e}")
        else:
            messagebox.showwarning("Warning", "Please enter an IP address or ID to search.")

    

    ip_label = tk.Label(modify_window, text="Modify your IP's from here :-", font=('Segoe UI', 12), fg='black', bg='#cce7ff')
    ip_label.pack(pady=5)

    search_frame = tk.Frame(modify_window, bg='#cce7ff')
    search_frame.pack(fill=tk.X, padx=10, pady=10)

    search_entry = tk.Entry(search_frame)
    search_entry.pack(side=tk.LEFT, padx=5)
    

    search_button = ttk.Button(search_frame, text="Search", command=search_ip)
    search_button.pack(side=tk.LEFT, padx=5)

    # Create a treeview with columns for S.No, IP, Priority, Location, and Remarks
    ip_tree = ttk.Treeview(modify_window, columns=("S.No", "ID", "IP", "Priority", "Location", "Remarks"), show="headings")
    ip_tree.heading("S.No", text="S.No")
    ip_tree.heading("ID", text="ID")
    ip_tree.heading("IP", text="IP")
    ip_tree.heading("Priority", text="Priority")
    ip_tree.heading("Location", text="Location")
    ip_tree.heading("Remarks", text="Remarks")
    ip_tree.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    refresh_button = ttk.Button(modify_window, text="Refresh List", command=refresh_ip_list)
    refresh_button.pack(pady=5)

    delete_button = ttk.Button(modify_window, text="Delete IP Address", command=delete_ip)
    delete_button.pack(pady=5)

    edit_button = ttk.Button(modify_window, text="Edit IP Address", command=edit_ip)
    edit_button.pack(pady=5)

    refresh_ip_list()



# Function to create a new window with styles, navbar, and gradient background
def create_new_window(title, geometry):
    new_window = tk.Toplevel(root)
    new_window.title(title)
    new_window.geometry(geometry)
    apply_styles(new_window)
    add_navbar(new_window)
    add_gradient_background(new_window)
    return new_window

# Function to apply styles to a given window
def apply_styles(window=None):
    style = ttk.Style()

    # Configure button style
    style.configure('TButton', 
                    background='#007fff', 
                    foreground='black',
                    font=('Segoe Ui', 10),
                    padding=5,
                    relief=tk.FLAT)

    # Configure label style
    style.configure('TLabel', 
                    foreground='black', 
                    font=('Segoe Ui', 10))

    # Configure entry style
    style.configure('TEntry',
                    font=('Segoe Ui', 10))

    # Configure listbox style
    style.configure('TListbox',
                    font=('Segoe Ui', 10))

    if window:
        # Set style for all ttk widgets in the new window
        window.option_add('*TCombobox*Listbox.font', ('Segoe Ui', 10))
        window.option_add('*TCombobox*Listbox.selectBackground', '#007fff')
        window.option_add('*TCombobox*Listbox.selectForeground', 'black')
        window.option_add('*TCombobox*Listbox.background', '#ffffff')

# Function to add navbar to a given window
def add_navbar(window):
    navbar_frame = tk.Frame(window, bg='#007fff', relief=tk.RAISED, borderwidth=1)
    navbar_frame.pack(side=tk.TOP, fill=tk.X)
    navbar_label = tk.Label(navbar_frame, text='Network Control Tool', font=('Segoe UI', 14), fg='white', bg='#007fff')
    navbar_label.pack(side=tk.LEFT, padx=10, pady=5)
    
    info_canvas = tk.Canvas(navbar_frame, width=20, height=20, bg='#007fff', highlightthickness=0)
    info_canvas.pack(side=tk.RIGHT, padx=10, pady=5)
    info_canvas.create_oval(0, 0, 15, 15, outline='white', fill='white')
    info_canvas.create_text(7, 7, text='i', font=('Segoe UI', 10), fill='#007fff')

    def show_info(event):
        info_window = tk.Toplevel(window)
        info_window.title("About")
        info_window.geometry("820x700")
        info_window.configure(bg='#edf0ee')

        canvas = tk.Canvas(info_window, bg='#edf0ee')
        scrollbar = tk.Scrollbar(info_window, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)

        info_frame = tk.Frame(canvas, bg='#edf0ee')
        canvas.create_window((0, 0), window=info_frame, anchor=tk.NW)

        info_label_about = tk.Label(info_frame, text="ABOUT", font=('Arial', 15, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT)
        info_label_about.pack(padx=20, pady=5, anchor=tk.W)

        info_label_description = tk.Label(info_frame, text="The Network Control Tool, developed as part of the ORDNANCE FACTORY DEHRADUN-(OFD) summer training program 2024, is a GUI-based application designed for monitoring and managing network devices using IP addresses.\n\nThis tool automates the network scanning process, optimizing manual device discovery. Users can schedule network scans at specified intervals, with the tool initiating scans and then pausing between cycles as per the set interval. This background scanning capability ensures efficient monitoring of network devices.", 
                                font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_description.pack(padx=20, pady=5, anchor=tk.W)

        info_label_instructions_heading = tk.Label(info_frame, text="Instructions:", font=('Arial', 14, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=470)
        info_label_instructions_heading.pack(padx=20, pady=5, anchor=tk.W)

        info_label_instructions = tk.Label(info_frame, text="1. 'Run Diagnostics' - starts network scan and prompts the disconnected nodes. It will repeat the diagnostics of all network after mentioned time interval \n\n2. 'Add IP Address' - to input new IP addresses, priority, location, and remarks.\n\n3. 'Modify IP Address' - to edit or delete existing IP entries.\n\n4. 'Terminate Diagnostics' - to stop ongoing diagnostics.\n\n5. 'Set Time Interval' to specify automatic pinging intervals (in seconds). ", 
                                font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_instructions.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_heading = tk.Label(info_frame, text="Developers' Corner:", font=('Arial', 14, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=470)
        info_label_developers_heading.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers = tk.Label(info_frame, text="This project is developed in the summer internship program of ORDNANCE FACTORY DEHRADUN-(OFD) 2024 under the guidance of Mr. Rajesh Tomar, by a team of four developers:-", font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_developers.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_tina = tk.Label(info_frame, text="1. Tina Mathpal - (MCA) - DIT University , Dehradun", font=('Arial', 12, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=470)
        info_label_developers_tina.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_tina_details = tk.Label(info_frame, text="FRONTEND:-\n\n - Designing and implementing the GUI using tkinter library.\n - Ensuring responsive layout and user-friendly design principles.", 
                                                    font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_developers_tina_details.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_divyansh = tk.Label(info_frame, text="2. Divyansh Negi - (B.Tech - IT) NIT Jalandhar", font=('Arial', 12, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=470)
        info_label_developers_divyansh.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_divyansh_details = tk.Label(info_frame, text="BACKEND & DATABASE:-\n\n - Implementing backend logic for handling IP address management (CRUD operations).\n - Handling threading for concurrent operations (using threading module).\n - Handling data validation and ensuring data integrity in database operations.", 
                                                    font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_developers_divyansh_details.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_mayank = tk.Label(info_frame, text="3. Mayank Nayal - (MCA) - RIT Roorkee ", font=('Arial', 12, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=470)
        info_label_developers_mayank.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_mayank_details = tk.Label(info_frame, text="FRONTEND & DATA MANAGEMENT:-\n\n - Adding features like gradient backgrounds, navbar, and pop-up dialogs (add_gradient_background, add_navbar functions).\n - Creating GUI components such as buttons, labels, entry fields, list boxes (tk.Button, tk.Label, tk.Entry, tk.Listbox, etc.).\n - Designing and creating the SQLite database schema (ip_address.db).", 
                                                    font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_developers_mayank_details.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_mohit = tk.Label(info_frame, text="4. Mohit Aditya - (B.Tech - AI) - JBIT Dehradun ", font=('Arial', 12, 'bold'), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=470)
        info_label_developers_mohit.pack(padx=20, pady=5, anchor=tk.W)

        info_label_developers_mohit_details = tk.Label(info_frame, text="TESTING & DOCUMENTATION:- \n\n - Writing comprehensive test cases to validate functionalities (unit testing).\n - Creating a detailed README file with setup instructions, dependencies, and project overview.\n - Providing support for bug fixing and ensuring code quality through code reviews.", 
                                                    font=('Segoe UI', 11), fg='black', bg='#edf0ee', justify=tk.LEFT, wraplength=770)
        info_label_developers_mohit_details.pack(padx=20, pady=5, anchor=tk.W)

        # Update scroll region
        info_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

        # Bind canvas to configure scroll region on resize
        def on_canvas_configure(event):
            canvas.config(scrollregion=canvas.bbox("all"))

        canvas.bind('<Configure>', on_canvas_configure)

        # Bind mousewheel event to scroll canvas
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        canvas.bind_all("<MouseWheel>", on_mousewheel)

    info_canvas.bind("<Button-1>", show_info)


# Function to add a gradient background to a given window
def add_gradient_background(window):
    canvas = tk.Canvas(window, width=window.winfo_width(), height=window.winfo_height(), highlightthickness=0)
    canvas.pack(fill=tk.BOTH, expand=True)

    def draw_gradient(canvas, width, height, color1, color2):
        r1, g1, b1 = window.winfo_rgb(color1)
        r2, g2, b2 = window.winfo_rgb(color2)
        r_ratio = (r2 - r1) / height
        g_ratio = (g2 - g1) / height
        b_ratio = (b2 - b1) / height
        for i in range(height):
            nr = int(r1 + (r_ratio * i))
            ng = int(g1 + (g_ratio * i))
            nb = int(b1 + (b_ratio * i))
            color = f'#{nr:04x}{ng:04x}{nb:04x}'
            canvas.create_line(0, i, width, i, fill=color, tags="gradient")

    canvas.bind("<Configure>", lambda event: draw_gradient(canvas, event.width, event.height, "#ffffff", "#cce7ff"))

# Function to open interval management window
def open_interval_window():
    interval_window = create_new_window("Interval Management", "300x250")

    def save_interval():
        interval = interval_entry.get().strip()
        if interval.isdigit() and int(interval) > 0:
            set_interval_value(int(interval))
            messagebox.showinfo("Success", f"Interval set to {interval} seconds.")
            interval_entry.delete(0, tk.END)
            update_current_interval_label()
        else:
            messagebox.showwarning("Warning", "Please enter a valid positive integer.")

    def update_current_interval_label():
        current_interval = get_interval_value()
        if current_interval:
            current_interval_label.config(text=f"Current Interval: {current_interval} seconds")
        else:
            current_interval_label.config(text="No Interval Set")

    interval_label = tk.Label(interval_window, text="Enter Interval (in seconds):", font=('Segoe UI', 12), fg='black', bg='#cce7ff')
    interval_label.pack(pady=5)

    interval_entry = tk.Entry(interval_window)
    interval_entry.pack(pady=5)

    save_button = ttk.Button(interval_window, text="Save Interval", command=save_interval)
    save_button.pack(pady=5)

    current_interval_label = tk.Label(interval_window, text="", font=('Segoe UI', 10), fg='black', bg='#cce7ff')
    current_interval_label.pack(pady=5)

    update_current_interval_label()

# Main GUI
root = tk.Tk()
root.title("IP Address Diagnostics")
root.geometry("300x400")

# Apply styles, add navbar, and add gradient background to the main window
apply_styles(root)
add_navbar(root)
add_gradient_background(root)

# Frame to contain buttons and use pack for layout
button_frame = tk.Frame(root, bg='#cce7ff')
button_frame.pack(fill=tk.BOTH, expand=True, pady=10)

# Buttons
run_button = ttk.Button(button_frame, text="Run Diagnostics", command=run_diagnostics)
run_button.pack(pady=10, padx=10, fill=tk.X)

add_button = ttk.Button(button_frame, text="Add IP Address", command=add_ip)
add_button.pack(pady=10, padx=10, fill=tk.X)

modify_button = ttk.Button(button_frame, text="Modify IP Address", command=modify)
modify_button.pack(pady=10, padx=10, fill=tk.X)

terminate_button = ttk.Button(button_frame, text="Terminate Diagnostics", command=terminate_diagnostics)
terminate_button.pack(pady=10, padx=10, fill=tk.X)

interval_button = ttk.Button(button_frame, text="Set time interval ", command=open_interval_window)
interval_button.pack(pady=10, padx=10, fill=tk.X)

# Label to show status
status_label = tk.Label(root, text="", font=('Segoe UI', 12), fg='black', bg='#cce7ff')
status_label.pack(pady=10)

# Create interval_table if it doesn't exist
create_interval_table()

# Start the main loop
root.mainloop()
