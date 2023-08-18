def draw_arrows(self):
    i = 2
    t = ''
    for node_dict in self.my_dict:
        print("calling arrows")
        for msg_name in node_dict.keys():
            for newmsg, values in node_dict[msg_name].items():
                if isinstance(values, dict):
                    src_node_name = values['src_node-src_ip']
                    dst_node_name = values['dst_node-dst_ip']
                    t = values['frame_time']
                    time_obj = datetime.datetime.strptime(t, '%Y-%m-%d-%H-%M-%S-%f')
                    formatted_time_str = time_obj.strftime('%H:%M:%S')

                    # Draw the arrow from the source to the destination node
                    src_x = self.node_centers[src_node_name]
                    dst_x = self.node_centers[dst_node_name]
                    # Draw the arrow from the source to the destination node
                    msg, fn = newmsg.split("_")
                    y = (i * 20) - 50
                    if node_dict[msg_name][newmsg]['src_node-src_ip'] != self.node_centers[src_node_name]:
                        self.canvas.create_line(src_x, y, dst_x, y, arrow='last', fill='black')
                        # canvas.create_text((src_x + dst_x) / 2, y - 17, text=msg + '(' + fn + ')', anchor='n')
                        # text_item = self.canvas.create_text((src_x + dst_x) / 2, y - 3,
                        #  text=msg + '(' + fn + ')(' + formatted_time_str + ')',
                        #  anchor='s')

                        # Define a tag with the desired formatting options
                        if msg.startswith('rrc'):
                            my_font = ('Helvetica', 10, 'italic')
                        else:
                            my_font = ('Helvetica', 10, 'italic')
                        # Create the text item with the tag applied to the "msg" portion of the text
                        text_item = self.canvas.create_text((src_x + dst_x) / 2, y - 3,
                                                            text=f"{msg} ({fn}) ({formatted_time_str})",
                                                            anchor='s', font=my_font, fill="blue")

                        self.canvas.tag_bind(text_item, '<Button-1>', self.on_click)

                    else:
                        self.canvas.create_line(dst_x, y - 2, src_x, y - 2, arrow='last', fill='black')
                        # canvas.create_text((dst_x + src_x) / 2, y - 17, text=msg + '(' + fn + ')', anchor='n')
                        text_item = self.canvas.create_text((src_x + dst_x) / 2, y - 1, text=msg + '(' + fn + ')',
                                                            anchor='s')
                        self.canvas.tag_bind(text_item, '<Button-1>', self.on_click)

                i += 1
    self.root.mainloop()
