class CommandLayerError(Exception):
    def __init__(self, message: str, status_code: int | None = None, details=None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details
