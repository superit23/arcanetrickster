from arcane.core.base_object import BaseObject

class DHCPOptions(BaseObject):
    def __init__(self, options: list):
        self.options = options
    

    def __str__(self):
        return str(self.options)


    def __getitem__(self, key):
        if type(key) is tuple:
            return [o for o in self.options if o == key]
        else:
            return [o for o in self.options if o[0] == key]


    def __setitem__(self, key, value):
        self.options.append((key, value))
    
    def __delitem__(self, key):
        matches = self[key]
        for m in matches:
            self.options.remove(m)


    def __contains__(self, key):
        return bool(len(self[key]))


    def __iter__(self):
        for o in self.options:
            yield o

    def remove_if_exists(self, key):
        if key in self:
            del self[key]
    

    def merge(self, other: "DHCPOptions", overwrite: bool):
        """
        Merges two `DHCPOptions` together. Does not mutate either.

        Parameters:
            other (DHCPOptions): The other options to pull from.
            overwrite    (bool): Whether to overwrite a duplicate option rather than append it. Options in `other` take precendence.

        Returns:
            DHCPOptions: New DHCPOptions.
        """
        if type(other) is not DHCPOptions:
            other = DHCPOptions.wrap(other)
        
        merged = self.deepcopy()

        if overwrite:
            # First, remove all duplicate keys
            for o in other:
                merged.remove_if_exists(o[0])
            
            # Then, add in `other`. Doing this in two separate loops is important!
            # It's possible that `other` has multiples and doing it in one loop would continuously overwrite those entries
            for o in other:
                merged.options.append(o)
        else:
            for o in other:
                if not o in merged:
                    merged.options.append(o)
        
        return merged


    @staticmethod
    def wrap(options: list):
        if type(options) is DHCPOptions:
            return options

        elif type(options) is list:
            return DHCPOptions(options)

        elif type(options) is dict:
            return DHCPOptions(list(options.items()))

        else:
            raise TypeError(f"Type {type(options)} is not usable by DHCPOptions")
