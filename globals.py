# hacky way to pass python objects around as bv only allows certain types
# adapted from https://github.com/borzacchiello/seninja/blob/f8da9abc318755d0ff23e584d51a35734920839c/globals.py
class Globals(object):
    primary_manager = None