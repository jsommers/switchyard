class SwitchyException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message

class ScenarioFailure(SwitchyException):
    pass

class Shutdown(Exception):
    '''Exception that is raised in user Switchyard program when the
    framework is being shut down.'''
    pass

class NoPackets(Exception):
    '''Exception that is raised in user Switchyard program when
    the recv_packet() method is called on the net object and there
    are no packets available.'''
    pass

