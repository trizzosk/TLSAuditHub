def diff_sets(old: set, new: set):
    return {
        "added": sorted(list(new - old)),
        "removed": sorted(list(old - new)),
    }


def diff_dict(old: dict, new: dict):
    changes = {}
    for key in old.keys() | new.keys():
        if old.get(key) != new.get(key):
            changes[key] = {
                "old": old.get(key),
                "new": new.get(key),
            }
    return changes

    