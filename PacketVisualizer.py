import ast
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import ttk
from tkinter.tix import IMAGETEXT

import PacketAnalyzerN
import PacketView


class PacketVisualizer:
    def __init__(self, master, ):
        self.master = master
        self.success_data = {}
        self.failure_data = {}
        self.my_dict = {}
        self.data = {}
        self.checkboxes = []
        self.success_table = None
        self.failure_table = None
        self.checkbox_frame = None
        self.setup_gui()
        self.counters = {}

        self.pcap_file = None
        # initialize fields_dict

    def setup_gui(self):
        self.master.geometry("800x600")
        self.master.title("PCAP ANALYZER")

        # search bar and button
        search_frame = ttk.Frame(self.master)
        search_frame.pack(side=tk.TOP, fill=tk.X)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.RIGHT, padx=5, pady=5, anchor=tk.NW)
        self.results_label = ttk.Label(search_frame, text="", foreground="red", background="white")
        self.results_label.lift()
        self.results_label.pack(pady=10)
        self.search_entry.bind("<KeyRelease>", self.search)
        self.search_entry.bind("<FocusIn>", self.clear_search_results)
       
        # create a button to export data
        self.export_button = ttk.Button(self.master, text="Export", command=self.export_data)
      
        # self.export_button.pack(side=tk.LEFT, padx=0, pady=0, anchor=tk.NW)
        self.export_button.place(x=5, y=5)
       
        # create the import button
        self.import_button = ttk.Button(self.master, text="Import", command=self.import_data)
        self.import_button.place(x=80, y=5)

        # create a button to select pcap file
        self.select_pcap_button = ttk.Button(self.master, text="PCAP file", command=self.select_pcap_file)
        self.select_pcap_button.pack()

    def select_pcap_file(self):
        # create a file dialog box to select pcap file
        pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        # do something with the selected pcap file path
        self.pcap_file = pcap_file
        if self.pcap_file:
            self.my_dict = None
            self.data == None
            self.checkboxes = []
            self.success_table = None
            self.failure_table = None
            self.checkbox_frame = None
            self.counters = {}

            # print(f"Selected PCAP file path: {self.pcap_file}")
            self.fetch_data()
            # print(" in PCAP file calling ", self.my_dict)
            # pass self.pcap_file_path to your function here

    def create_canvas(self):
        # create a canvas widget and pack it
        canvas = tk.Canvas(self.master, width=800, height=600)
        canvas.pack(fill=tk.BOTH, expand=True)

        # load the background image and add it to the canvas
        bg_image = Image.open("background.png")
        bg_image = bg_image.resize((800, 600), Image.ANTIALIAS)
        bg_image_tk = IMAGETEXT.PhotoImage(bg_image)
        canvas.create_image(0, 0, image=bg_image_tk, anchor=tk.NW)

    def export_data(self):
        # prompt user to select a file name and location
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")

        if not file_path:
            return

        # open file for writing
        with open(file_path, "w") as f:
            # write fields_dict to file
            for key, value in self.my_dict.items():
                f.write(f"{{{key}:{value}}}\n")

        # notify user that data has been exported
        print("Data exported successfully!")

    def import_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r") as file:
                merged_data = {}
                for line in file:
          
                    # remove leading/trailing whitespaces and curly braces from the line
                    line = line.strip().strip("{").replace("}}}", "}}")
                    key, value = line.split(":", 1)
                    # convert the string representation of the dictionary to an actual dictionary
                    value_dict = ast.literal_eval(value.strip())
                    # update the merged_data dictionary with the key-value pair
                    merged_data[key] = value_dict

                # Do something with the imported data
                self.my_dict = merged_data
                self.fetch_data('False')

    def fetch_data(self, local='True'):
        if local == 'True':
            pa = PacketAnalyzerN.PacketAnalyzerN(self.pcap_file)
            self.my_dict = pa.packet_analyzer()
      

        # self.my_dict = PacketAnalyzer.packetAnalyzer(self.pcap_file)

        # Define the message counters dictionary
        counters = {
            "rrcSetupRequest": {"success": 0, "failure": 0},
            "securityModeCommand": {"success": 0, "failure": 0, "attempt": 0},
            "BearerContextSetupRequest": {"success": 0, "failure": 0, "attempt": 0},
            "registrationRequest": {"success": 0, "failure": 0},
            "InitialContextSetupRequest": {"success": 0, "failure": 0},
        }
        # Update the message counters dictionary based on the input data
        for key, values in self.my_dict.items():
            for message, result in values.items():
                if message in counters:
                    if result == "Success":
                        counters[message]["success"] += 1
                    elif result == "Failure":
                        counters[message]["failure"] += 1
                    elif result == "Attempt":
                        counters[message]["failure"] += 1
        # Define the message-wise table headers
        table_headers = ["Key", "Message", "Pci", "Result"]
        # Define the rows for the table
        table_rows = []
        pci = None
        for key, values in self.my_dict.items():
            for message, result in values.items():
                if message in counters:
                    if message == "rrcSetupRequest":
                        pci = values.get("pci")
                        table_rows.append([key, message, pci, result])
                    else:
                        table_rows.append([key, message, pci, result])

        # Return the message-wise counters and the table
        self.checkbox_labels(counters, local)
        self.data = table_rows
        self.result_tables(table_rows, local)

        # return counters, table_headers, table_rows

    def update_tables(self):
        # Get the selected checkboxes
        selected_checkboxes = []
   
        for checkbox in self.checkboxes:

            if checkbox.var.get() == 1:
                selected_checkboxes.append(checkbox.message)

        # Filter the data based on the selected checkboxes
        success_data = [row for row in self.data if row[2] == "Success" and row[1] in selected_checkboxes]
        failure_data = [row for row in self.data if row[2] in ["Failure", "Attempt"] and row[1] in selected_checkboxes]
        data = success_data + failure_data

    def checkbox_labels(self, counters, local='True'):
        if local != "True" and self.checkbox_frame is not None:
            self.checkbox_frame.pack_forget()

        self.checkbox_frame = tk.Frame(self.master)
        self.checkbox_frame.pack(side="top", anchor="w")
        checkboxes = []

        # create a checkbox for each message in the counters dictionary
        # loop over each message in counters dictionary and create Checkbutton with count number
        i = 0
        for message, values in counters.items():
            count_text = f" ({values['success']} \u2713),({values['failure']}\u2717)"
            checkbox_text = message + count_text
            var = tk.IntVar(value=0)
            checkbox = tk.Checkbutton(self.checkbox_frame, text=checkbox_text, variable=var, command=self.filter_data)
            # arrange the checkboxes in a 2x5 grid
            row = i // 5
            column = i % 5
            checkbox.grid(row=row, column=column, sticky="w")
            i += 1
            checkbox.message = message
            checkbox.var = var
            self.checkboxes.append(checkbox)

    def filter_data(self):
        # Get the selected checkboxes
        selected_checkboxes = [checkbox for checkbox in self.checkboxes if checkbox.var.get() == 1]
      
        # Get the names of the selected checkboxes
        selected_names = [checkbox.message for checkbox in selected_checkboxes]


        # Use the selected names to filter the data and update the tables
        filtered_data = [d for d in self.data if d[1] in selected_names]
        if filtered_data != [] and selected_names != []:
            # update the current table
            self.update_treeview(self.failure_table, self.success_table, filtered_data)
        elif selected_checkboxes == []:
            self.update_treeview(self.failure_table, self.success_table, self.data)
            self.results_label.config(text="")
        else:
            self.results_label.config(text="No search results found.", foreground="red")
            self.update_treeview(self.failure_table, self.success_table, self.data)

    def clear_search_results(self, event):
        self.search_entry.delete(0, tk.END)
        self.update_treeview(self.failure_table, self.success_table, self.data)

    def search(self, event):
        results = []

        search_text = self.search_entry.get()
 
        if search_text != '':
            results = [d for d in self.data if
                       str(d[0]).startswith(search_text.lower()) or str(
                           d[1]).lower().startswith(search_text.lower()) or str(
                           d[2]).lower().startswith(search_text.lower())]

            if results != []:
                self.update_treeview(self.failure_table, self.success_table, results)
                count = len(results)
                self.results_label.config(text=f"{count} matching results", foreground="green")

            else:
                self.results_label.config(text="No search results found.", foreground="red")
        else:
            self.update_treeview(self.failure_table, self.success_table, self.data)
            self.results_label.config(text="")

    def update_treeview(self, failure, success, data):
        if isinstance(data, list):
            failure.delete(*failure.get_children())
            success.delete(*success.get_children())
            # Populate the tables
            for item in data:
           
                key, message, pci, result = item
                if result == "Success":
                    self.success_table.insert("", tk.END, values=item)
                elif result == "Failure" or result == "Attempt" and item is not None:
                    self.failure_table.insert("", tk.END, values=item)
        elif isinstance(data, None):
            tree.delete(*tree.get_children())

    def open_flow_visualizer(self, id):
        test = {}
        y = None

        for y, x in self.my_dict.items():
            if y == id:
                test[y] = x
        PacketView.PacketView([test])

    def on_select(self, event):
        # get the selected item from the tree view
        selected_item = event.widget.selection()[0]
        # get the values of the selected item
        values = event.widget.item(selected_item, "values")
        # pass the ID to your packet flow widget
        self.open_flow_visualizer(values[0])

    def result_tables(self, data, local):
        if local == 'True':
            headers = ["KEY", "MESSAGE", "PCI", "RESULT"]
            success_frame = ttk.Frame(self.master)
            success_frame.pack(side=tk.LEFT, padx=0, fill=tk.BOTH, expand=True)
            # success_frame.pack(side="left", anchor="nw", padx=10, pady=10, expand=True)
            success_label = ttk.Label(success_frame, text="Success List")
            success_label.pack()
            self.success_table = ttk.Treeview(success_frame, columns=headers, show="headings")
            for header in headers:
                self.success_table.heading(header, text=header)
                self.success_table.column(header, width=100)
            self.success_table.pack(side="right", padx=10, pady=10, fill="y")
            # self.success_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            success_scrollbar = ttk.Scrollbar(success_frame, orient="vertical", command=self.success_table.yview)
            success_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.success_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self.success_table.configure(yscrollcommand=success_scrollbar.set)
            # self.update_treeview(success_tree, data)
            self.success_table.bind("<<TreeviewSelect>>", self.on_select)
            self.success_table.pack_propagate(False)  # Disable automatic size control by parent
            self.success_table.column("#0", width=8, stretch=tk.NO)  # remove first column
            # Setting up Failure tables
            failure_frame = ttk.Frame(self.master)
            failure_frame.pack(side=tk.LEFT, padx=0, fill=tk.BOTH, expand=True)

            # success_frame.pack(side="left", anchor="nw", padx=10, pady=10, expand=True)
            failure_label = ttk.Label(failure_frame, text="Failure List")
            failure_label.pack()
            self.failure_table = ttk.Treeview(failure_frame, columns=headers, show="headings")
            for header in headers:
                self.failure_table.heading(header, text=header)
                self.failure_table.column(header, width=100)
            self.failure_table.pack(side="left", padx=10, pady=10, fill="y")
            # self.failure_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            failure_scrollbar = ttk.Scrollbar(failure_frame, orient="vertical", command=self.failure_table.yview)
            failure_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.failure_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self.failure_table.configure(yscrollcommand=failure_scrollbar.set)
            # self.update_treeview(success_tree, data)
            self.failure_table.bind("<<TreeviewSelect>>", self.on_select)
            self.failure_table.pack_propagate(False)  # Disable automatic size control by parent
            self.failure_table.column("#0", width=8, stretch=tk.NO)  # remove first column
        self.update_treeview(self.failure_table, self.success_table, self.data)

if __name__ == "__main__":
    root = tk.Tk()

    PacketVisualizer(root)

    root.mainloop()
