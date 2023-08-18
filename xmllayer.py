class xmllayer:
    def __init__(self, layer):
        self.packet = layer
        t = self.packet.xml_format()
        b = self.packet.ngap.get_field_by_showname()
        print(t)
        for i in b:
            print("items:", )
