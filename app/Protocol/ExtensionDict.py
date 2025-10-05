from Protocol.Extension_Protocol import extension_mapping

# classes = [x for x in Protocol.Extension_Protocol.__dict__.values() if isinstance(x,type)]


class ExtensionDict:
    """
    extension dictionary enabling reverse lookup
    """
    def __init__(self, source_dict):
        self.source_dict = source_dict
        self.mapping = {}
        self.update_mapping()
    
    def update_mapping(self):
        self.mapping = {
            source[1]:extension_mapping[source[0]] for source in self.source_dict['m'].items()
            if source[0] in extension_mapping and source[1] != 0
        }
    
    def add_extension(self, extension, extension_id):
        #might as well use update()
        self.source_dict['m'][extension.name]=extension_id
        self.update_mapping()
        return {extension.name:extension_id}
    
    def update(updates):
        # self.source_dict |= updates
        for name, extension_id in updates.items():
            self.source_dict['m'][name]=extension_id
        self.update_mapping()
        # return {name:extension_id for name,extension_id in updates}
    
    def __contains__(self, extension):
        if extension in self.source_dict['m']:
            return True 
        return False
    
    def __getitem__(self, index):
        return self.source_dict[index]
    
    def __str__(self):
        return str(self.source_dict)