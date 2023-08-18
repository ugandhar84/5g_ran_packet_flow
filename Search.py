import tkinter as tk


class Search(tk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

        # create text widget to demonstrate search
        self.text_widget = tk.Text(self)
        self.text_widget.pack(fill=tk.BOTH, expand=True)

        # bind Ctrl+F to search function
        self.master.bind('<Control-f>', self.search)

    def search(self, event=None):
        # open search dialog or activate search bar
        pass
