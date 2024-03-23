import random

def random_mac():
    mac = random.randint(0, 2**48-1)

    # Set the broadcast bit
    if not mac & 2**40:
        mac ^= 2**40

    mac = hex(mac)[2:].zfill(12)
    return f'{mac[:2]}:{mac[2:4]}:{mac[4:6]}:{mac[6:8]}:{mac[8:10]}:{mac[10:12]}'


def binary_search_list(in_list: list, value: object, key: 'FunctionType'=lambda item: item, fuzzy: bool=False) -> int:
    """
    Performs binary search for `value` on a sorted `in_list` with key selector `key`.

    Parameters:
        in_list (list): Sorted list to search.
        value (object): Value to search for.
        key     (func): Function that takes in an item and returns the key to search over.

    Returns:
        int: Index of value.
    """
    start_range = 0
    end_range   = len(in_list)

    if not end_range or value > key(in_list[-1]):
        if fuzzy:
            return end_range
        else:
            raise IndexError("Item not in list")


    if value < key(in_list[0]):
        if fuzzy:
            return start_range
        else:
            raise IndexError("Item not in list")

    curr     = -1
    fuzz_mod = 0
    while end_range - 1 != start_range:
        curr = (end_range - start_range) // 2 + start_range
        item = key(in_list[curr])

        if item == value:
            return curr
        elif item < value:
            start_range = curr
            fuzz_mod    = 1
        else:
            end_range = curr
            fuzz_mod  = 0

    # Special case since at zero, end_range - 1 == start_range
    if key(in_list[0]) == value:
        return 0

    if fuzzy:
        return curr + fuzz_mod
    else:
        raise IndexError("Item not in list")

