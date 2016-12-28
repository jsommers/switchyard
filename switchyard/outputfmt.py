class VerboseOutput(object):
    _on = False

    @staticmethod
    def enable():
        VerboseOutput._on = True

    @staticmethod
    def disable():
        VerboseOutput._on = False

    @staticmethod
    def enabled():
        return VerboseOutput._on
