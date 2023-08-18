import datetime
import json
import tkinter as tk

import yaml

import frameView


class PacketView:
    def __init__(self, my_dict):
        self.my_dict = my_dict
        self.max_msg_length = max(
            len(key) for message_dict in self.my_dict for node_dict in message_dict.values() for key in
            node_dict.keys())
        self.node_set = set()

        self.crnti_duid = None
        for message_dict in self.my_dict:
            for key, node_dict in message_dict.items():
                self.crnti_duid = key
                for message_key, message_value in node_dict.items():
                    if isinstance(message_value, dict):
                        src_node = f"{message_value['src_node']}"
                        self.node_set.add(src_node)
                        dst_node = f"{message_value['dst_node']}"
                        self.node_set.add(dst_node)
   

        self.root = tk.Tk()
        self.root.geometry('1000x2000')
        self.root.title("Call Flow for CNTI_DUID: " + self.crnti_duid)
        self.node_spacing = 160
        #self.spacing = 200
        self.text_box_offset = 10
        self.canvas_width = 1500
        self.canvas_height = 1000
        self.preferred_order = ['NgNB-DU', '0', 'NgNB-CUCP', "0", 'NgNB-CUUP',"0", "NgAMF","0","xnCUCP" ]
        self.node_centers = {}
        self.create_widgets()
        self.draw_arrows()
        self.scale = 1.0  # initial scale
        self.bind("<MouseWheel>", self.zoom)
        self.scale("all", 0, 0, self.scale, self.scale, expand=True)
        self.node_name_txt = None

    def scroll_canvas(self, event):
        if event.delta:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def zoom(self, event):
        # Zoom in with Ctrl+scroll up, zoom out with Ctrl+scroll down
        if event.state == 0x0004:
            self.scale *= 1.1
        elif event.state == 0x0005:
            self.scale /= 1.1

        # Update the canvas scale

    def create_widgets(self):
        # create a canvas with scrollbars for both x and y directions
        self.canvas = tk.Canvas(self.root, width=self.canvas_width, height=self.canvas_height,
                                scrollregion=(0, 0, 2000, 5000), bg='black')
        self.xscrollbar = tk.Scrollbar(self.root, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.yscrollbar = tk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.config(xscrollcommand=self.xscrollbar.set, yscrollcommand=self.yscrollbar.set)

        # pack the scrollbars and canvas
        self.xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.yscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, )

        # create a frame to hold the content in the canvas
        self.frame = tk.Frame(self.canvas, bg='white')
        self.canvas.create_window((0, 0), window=self.frame, anchor='nw')
        self.canvas.bind_all("<MouseWheel>", self.scroll_canvas)
        self.canvas.pack()

        # Create rectangles and labels for each node based on their position in the node_positions dictionary
        for i, node_prefix in enumerate(self.preferred_order):
            node_names = [node_name for node_name in self.node_set if node_name.startswith(node_prefix)]
            node_dict = {}
            for node in self.node_set:
                prefix, ip = node.split('_')
                node_dict.setdefault(prefix, []).append(ip)

            # merge nodes with same prefix
            # merged_nodes = set()
            # for prefix, ips in node_dict.items():
            #     if len(ips) > 1:
            #         merged_nodes.add(f"{prefix}_{'_'.join(sorted(ips))}")
            #     else:
            #         merged_nodes.add(f"{prefix}_{''.join(sorted(ips))}")
            # # combine merged and non-merged nodes
            # print("merged_nodes", merged_nodes)
            for node_name in node_names:
                x0 = i * self.node_spacing + 90
                y0 = 60
                # for element in merged_nodes:
                #     if element.startswith(node_name.split("_")[0]):
                #         self.node_name_txt = element
                #     else:
                #         self.node_name_txt = node_name

                #print(self.node_name_txt)
                text_item = self.canvas.create_text(x0, y0, text=f"{node_name}", anchor='n')
                bbox = self.canvas.bbox(text_item)
                x1, y1 = bbox[2] + self.text_box_offset, bbox[3] + self.text_box_offset
                self.canvas.create_rectangle(bbox[0] - self.text_box_offset, bbox[1] - self.text_box_offset, x1 - 1,
                                             y1 - 1,
                                             fill='pale goldenrod',
                                             outline='gray', width=2)

                self.canvas.create_text((bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2, text=f'{node_name}',
                                        anchor='center')

                # Draw vertical lines from node box to ladder
                x_center = (bbox[0] + bbox[2]) / 2
                center_x = (bbox[0] + bbox[2]) / 2
                self.node_centers[node_name] = center_x

                self.canvas.create_line(x_center, y1, x_center, y1 + 3500, width=2, fill='white')

    def on_click(self, event):
        message = event.widget.itemcget(event.widget.find_withtag('current')[0], 'text')
        output_str = message[:message.rfind('(')]
        m = output_str.replace(' (', '_').replace(')', '').replace(" ", "")
        for message_dict in self.my_dict:
            for node_dict in message_dict.values():
                for message_key, message_value in node_dict.items():
                    if isinstance(message_value, dict) and message_key == m:
                        packet = message_value['packet']
                        # self.reqformat(packet)
                        self.packet_to_dict(packet)

    def packet_to_dict(self, packet):
        # Extract IP layer if it exists
        new_dict = {}

        for key in packet:
            # split the key by the first dot and get the top-level key and the second-level key suffix
            if "." in key:
                top_level_key, suffix = key.split(".", 1)
            else:
                top_level_key = key
                suffix = ""

            # create a new dictionary with the top-level key if it doesn't exist
            if top_level_key not in new_dict:
                new_dict[top_level_key] = {}

            # add the second-level key suffix and its value to the new dictionary
            new_dict[top_level_key][suffix] = packet[key]
        # convert the output dictionary to a pretty-printed JSON string
        output_str = json.dumps(new_dict, indent=4)


        # Print packet dictionary in JSON format
        frameView.frameView(output_str)
        # return output_str

    def reqformat(self, packet):

        k = packet.ngap._get_all_field_lines()
        j = {i.strip() for i in k if
             ':' in i and "id: id-" not in i and "protocolIEs" not in i and "criticality:" not in i and "Item " not in i}
        t = sorted(j)
        # Split each string into key-value pairs
        kv_pairs = [s.strip().split(':', 1) for s in t]
        # Create dictionary from key-value pairs
        json_dict = {k: v for k, v in kv_pairs}
        # Convert dictionary to JSON string
        json_str = json.dumps(json_dict)
        y = yaml.dump(t)
        # frameView.frameView(y)

    def draw_arrows(self):
        i = 2
        t = ''
        y = (i * 70)
        for node_dict in self.my_dict:
            for msg_name in node_dict.keys():
                for newmsg, values in node_dict[msg_name].items():
                    if isinstance(values, dict):
                        src_node_name = values['src_node']
                        dst_node_name = values['dst_node']
                        t1 = values['frame_time']
                        t1 = datetime.datetime.fromtimestamp(float(t1))
                        t1 = t1.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d-%H-%M-%S-%f')
                        t1 = datetime.datetime.strptime(t1, '%Y-%m-%d-%H-%M-%S-%f')
                        formatted_time_str = t1.strftime('%H:%M:%S')
                        # Draw the arrow from the source to the destination node
                        src_x = self.node_centers[src_node_name]
                        dst_x = self.node_centers[dst_node_name]
                        # Draw the arrow from the source to the destination node
                        msg, fn = newmsg.split("_")

                        if node_dict[msg_name][newmsg]['src_node'] != self.node_centers[src_node_name]:
                            self.canvas.create_line(src_x, y, dst_x, y, arrow='last', fill='white')
                            # canvas.create_text((src_x + dst_x) / 2, y - 17, text=msg + '(' + fn + ')', anchor='n')
                            # text_item = self.canvas.create_text((src_x + dst_x) / 2, y - 3,
                            #  text=msg + '(' + fn + ')(' + formatted_time_str + ')',
                            #  anchor='s')

                            # Define a tag with the desired formatting options
                            if msg.startswith('rrc'):
                                my_font = ('Helvetica', 9, 'italic')
                            else:
                                my_font = ('Helvetica', 9, 'italic')
                            # Create the text item with the tag applied to the "msg" portion of the text
                            text_item = self.canvas.create_text((src_x + dst_x) / 2, y - 2,
                                                                text=f"{msg} ({fn}) ({formatted_time_str})",
                                                                anchor='s', font=my_font, fill="white")

                            self.canvas.tag_bind(text_item, '<Button-1>', self.on_click)
                            y = (i * 25) - 80
                        else:
                            self.canvas.create_line(dst_x, y - 2, src_x, y - 2, arrow='last', fill='black')
                            # canvas.create_text((dst_x + src_x) / 2, y - 17, text=msg + '(' + fn + ')', anchor='n')
                            text_item = self.canvas.create_text((src_x + dst_x) / 2, y - 1, text=msg + '(' + fn + ')',
                                                                anchor='s')
                            self.canvas.tag_bind(text_item, '<Button-1>', self.on_click)

                    i += 1.3
        self.root.mainloop()
