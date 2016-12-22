class SwitchyardException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message

class Shutdown(SwitchyardException):
    '''Exception that is raised in user Switchyard program when the
    framework is being shut down.'''
    def __init__(self, *args):
        SwitchyardException.__init__(self, "Framework shutdown")
    

class NoPackets(SwitchyardException):
    '''Exception that is raised in user Switchyard program when
    the recv_packet() method is called on the net object and there
    are no packets available.'''
    def __init__(self, *args):
        SwitchyardException.__init__(self, "No packets available")

class NotEnoughDataError(SwitchyardException):
    '''Exception that is raised when attempting to build a packet
    header object from a bytes object, but there aren't enough bytes
    to perform the reconstruction.'''
    pass
