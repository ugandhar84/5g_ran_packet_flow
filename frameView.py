import tkinter as tk

import Search


def frameView(json_packet):
    # Create the main window
    root = tk.Tk()
    root.geometry('500x600')  # set the window size to 200x100

    root.title("Packet View")

    # Create a scrollable text widget
    text_widget = tk.Text(root, wrap="none")
    text_widget.pack(fill="both", expand=True)

    # Set the content of the text widget
    text_widget.insert("1.0", json_packet)
    root.bind('<Control-f>', search_text)
    # Add horizontal and vertical scrollbars to the text widget
    h_scrollbar = tk.Scrollbar(text_widget, orient="horizontal", command=text_widget.xview)
    h_scrollbar.pack(side="bottom", fill="x")
    v_scrollbar = tk.Scrollbar(text_widget, orient="vertical", command=text_widget.yview)
    v_scrollbar.pack(side="right", fill="y")
    text_widget.configure(xscrollcommand=h_scrollbar.set, yscrollcommand=v_scrollbar.set)


def search_text(event=None):
    root = tk.Tk()
    search_window = Search.SearchDialog(root, "Search")
    search_window.show()
    search_term = search_window.text
    if search_term:
        search_and_highlight(search_term)


def search_and_highlight(search_term):
    root = tk.Tk()
    text_widget = tk.Text(root, wrap="none")
    text_widget.pack(fill="both", expand=True)
    # Remove any previous highlighting
    text_widget.tag_remove("highlight", "1.0", "end")

    # Find all occurrences of the search term
    start = "1.0"
    while True:
        start = text_widget.search(search_term, start, "end")
        if not start:
            break
        end = f"{start}+{len(search_term)}c"
        text_widget.tag_add("highlight", start, end)
        start = end

        # Highlight all occurrences of the search term with a yellow background
    text_widget.tag_config("highlight", background="yellow")

    root.mainloop()
