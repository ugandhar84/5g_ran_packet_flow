import tkinter as tk
from tkinter import ttk

import PacketAnalyzer
import PacketView


class PacketVisualizer:
    def __init__(self, master, pcap_file):
        self.master = master
        self.pcap_file = pcap_file
        self.success_data = {}
        self.rrc_success_data = {}
        self.rrc_failure_data = {}
        self.failure_data = {}
        self.my_dict = {}
        self.success_tree = None
        self.failure_tree = None
        self.setup_gui()
        # fetch Data
        self.fetch_data()
        self.fetch_data1()

        self.checkboxes = []

    def setup_gui(self):
        self.master.geometry("800x600")
        self.master.title("PCAP ANALYZER")
        # search bar and button
        search_frame = ttk.Frame(self.master)
        search_frame.pack(pady=10)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        search_button = ttk.Button(search_frame, text="Search", command=self.search)
        search_button.pack(side=tk.LEFT)
        self.results_label = ttk.Label(search_frame, text="", foreground="red", background="white")
        self.results_label.lift()

        self.results_label.pack(pady=10)

        self.search_entry.bind("<KeyRelease>", self.search)
        self.search_entry.bind("<FocusIn>", self.clear_search_results)
        # create a frame to hold the checkboxes
        self.checkbox_frame = tk.Frame(root)
        self.checkbox_frame.pack(side="top", anchor="nw")

        # create a list to hold the checkboxes
        self.checkboxes = []

    def update_counters(self, data):
        # reset all counters to zero
        for message, counts in self.counters.items():
            counts["success"] = 0
            counts["failure"] = 0
            counts["attempt"] = 0

        # update the counters based on the data
        for key, values in data.items():
            for message, status in values.items():
                if message in self.counters:
                    counters[message][status] += 1

        # update the labels with the new counter values
        for message, var in checkboxes:
            if var.get():
                success_count = self.counters[message]["success"]
                failure_count = (self.counters[message]["failure"] + self.counters[message]["attempt"])

                labels[f"{message}_success"].configure(text=f"({success_count})")
                labels[f"{message}_failure"].configure(text=f"({failure_count})")
            else:
                labels[f"{message}_success"].configure(text="(0)")
                labels[f"{message}_failure"].configure(text="(0)")

    def checkbox_labels(self, counters):
        print(counters)
        # create a frame to hold the checkboxes
        checkbox_frame = tk.Frame(self.master)
        checkbox_frame.pack(side="top", anchor="w")

        # create a list to hold the checkboxes
        checkboxes = []

        # create a checkbox for each message in the counters dictionary
        # loop over each message in counters dictionary and create Checkbutton with count number
        for message, values in counters.items():
            count_text = f" ({values['success']} \u2713),({values['failure']}\u2717)"
            checkbox_text = message + count_text
            var = tk.IntVar(value=1)
            checkbox = tk.Checkbutton(checkbox_frame, text=checkbox_text, variable=var)
            checkbox.pack(side="top", anchor="w")

    def fetch_data1(self):
        # Define the message counters dictionary
        counters = {
            "rrcSetupRequest": {"success": 0, "failure": 0},
            "securityModeCommand": {"success": 0, "failure": 0, "attempt": 0},
            "BearerContextSetup": {"success": 0, "failure": 0, "attempt": 0},
            "UeContextRelase": {"success": 0, "failure": 0},
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
        table_headers = ["Key", "Message", "Result"]
        # Define the rows for the table
        table_rows = []
        for key, values in self.my_dict.items():
            for message, result in values.items():
                if message in counters:
                    table_rows.append([key, message, result])
        # Return the message-wise counters and the table
        self.checkbox_labels(counters)
        return counters, table_headers, table_rows

    def fetch_data(self):
        self.my_dict = PacketAnalyzer.packetAnalyzer(self.pcap_file)

        # Getting RRC Success Failure data Kye as CRNTI_DU_F1AP IDs
        for message_dict in self.my_dict.items():
            for key in message_dict:
                crnti = message_dict[0]
                crnti_data = message_dict[1]
                if message_dict[1]['rrcSetupRequest'] == "Success":
                    if message_dict[0] not in self.success_data:
                        self.success_data[message_dict[0]] = {"id": message_dict[0],
                                                              'rrcStatus': message_dict[1]['rrcSetupRequest']}
                elif message_dict[1]['rrcSetupRequest'] != '':
                    if message_dict[0] not in self.failure_data:
                        self.failure_data[message_dict[0]] = {"id": message_dict[0],
                                                              'rrcStatus': message_dict[1]['rrcSetupRequest']}
        # Succ or Fail Display results in table
        self.result_tables()

    def clear_search_results(self, event):
        self.search_entry.delete(0, tk.END)
        self.update_treeview(self.success_tree, self.success_data)
        self.update_treeview(self.failure_tree, self.failure_data)

    def search(self, event):
        success_results = []
        failure_results = []
        search_text = self.search_entry.get()

        if search_text != '':
            success_results = [d for d in self.success_data.values() if
                               search_text.lower() in str(d["id"]).lower() or search_text.lower() in str(
                                   d["rrcStatus"]).lower()]

            failure_results = [d for d in self.failure_data.values() if
                               search_text.lower() in str(d["id"]).lower() or search_text.lower() in str(
                                   d["rrcStatus"]).lower()]

            if success_results != []:
                self.update_treeview(self.success_tree, success_results)
            else:
                self.update_treeview(self.success_tree, self.success_data)

            if failure_results != []:
                self.update_treeview(self.failure_tree, failure_results)
            else:
                self.update_treeview(self.failure_tree, self.failure_data)

            self.results_label.config(text="")
        else:
            self.update_treeview(self.success_tree, self.success_data)
            self.update_treeview(self.failure_tree, self.failure_data)
            self.results_label.config(text="No search results found.", foreground="red")

    def update_treeview(self, tree, data):
        # delete existing items in treeview
        # add new items to treeview
        if isinstance(data, dict):
            tree.delete(*tree.get_children())
            for i, v in data.items():
                tree.insert("", "end", values=(v["id"], v["rrcStatus"]))
        elif isinstance(data, list) and data != []:
            tree.delete(*tree.get_children())
            for item in data:
                tree.insert("", "end", values=(item["id"], item["rrcStatus"]))
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
        # pass the ID to your own widget
        self.open_flow_visualizer(values[0])

    def result_tables(self):
        success_frame = ttk.Frame(self.master)
        success_frame.pack(side=tk.LEFT, padx=0, fill=tk.BOTH, expand=True)
        success_label = ttk.Label(success_frame, text="Success List")
        success_label.pack()
        success_tree = ttk.Treeview(success_frame, columns=("id", "rrcStatus"))
        success_tree.heading("id", text="id")
        success_tree.heading("rrcStatus", text="rrcStatus")
        success_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        success_scrollbar = ttk.Scrollbar(success_frame, orient="vertical", command=success_tree.yview)
        success_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        success_tree.configure(yscrollcommand=success_scrollbar.set)
        self.success_tree = success_tree
        self.update_treeview(success_tree, self.success_data)
        success_tree.bind("<<TreeviewSelect>>", self.on_select)
        success_frame.pack_propagate(False)  # Disable automatic size control by parent
        success_tree.column("#0", width=8, stretch=tk.NO)  # remove first column

        # failure table
        failure_frame = ttk.Frame(self.master)
        failure_frame.pack(side=tk.LEFT, padx=0, fill=tk.BOTH, expand=True)
        failure_label = ttk.Label(failure_frame, text="Failure List")
        failure_label.pack()
        failure_tree = ttk.Treeview(failure_frame, columns=("id", "rrcStatus"))
        failure_tree.heading("id", text="id")
        failure_tree.heading("rrcStatus", text="rrcStatus")
        failure_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        failure_scrollbar = ttk.Scrollbar(failure_frame, orient="vertical", command=failure_tree.yview)
        failure_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        failure_tree.configure(yscrollcommand=failure_scrollbar.set)
        self.failure_tree = failure_tree
        self.update_treeview(failure_tree, self.failure_data)
        failure_tree.bind("<<TreeviewSelect>>", self.on_select)
        failure_frame.pack_propagate(False)  # Disable automatic size control by parent
        failure_tree.column("#0", width=2, stretch=tk.NO)  # remove first column


if __name__ == "__main__":
    root = tk.Tk()
    pcap_file = r'smc_failed.pcap'
    PacketVisualizer(root, pcap_file)
    root.mainloop()
