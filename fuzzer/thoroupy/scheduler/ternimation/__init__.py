from .termination import TerminationManager

class StopExecution(Exception):
    pass

class MeetCondition(Exception):
    pass