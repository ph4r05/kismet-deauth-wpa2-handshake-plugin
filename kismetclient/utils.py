import inspect


def csv(val):
    if isinstance(val, basestring):
        return val.split(',')
    elif hasattr(val, '__iter__'):
        return ','.join(map(str, val))
    else:
        raise TypeError('Must supply a comma separated string or an iterable')


def get_pos_args(func):
    """ Return the names of a function's positional args. """
    return inspect.getargspec(func).args[1:]


def get_csv_args(func):
    """ Return a csv string of a function's positional args. """
    return csv(get_pos_args(func))
