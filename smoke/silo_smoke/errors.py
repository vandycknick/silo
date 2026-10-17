class SmokeError(Exception):
    """Base error for the smoke harness."""


class SmokeEnvironmentError(SmokeError):
    """The host cannot run the requested smoke lane."""


class SmokeAssertion(SmokeError):
    """A bounded smoke operation did not meet its expectation."""
