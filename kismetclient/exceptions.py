class ServerError(Exception):
    """ Exception raised for errors captured from the Kismet Server. """

    def __init__(self, cmd, text):
        self.cmd = cmd
        self.text = text

    def __str__(self):
        return 'ID: %d CMD: "%s" ERROR: "%s"' % (self.cmd.command_id,
                                                 self.cmd.command,
                                                 self.text)
