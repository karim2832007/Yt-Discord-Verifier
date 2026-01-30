import datetime

class Logger:

    @staticmethod
    def log(*args):
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}]", *args)

    @staticmethod
    def error(*args):
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[ERROR {timestamp}]", *args)