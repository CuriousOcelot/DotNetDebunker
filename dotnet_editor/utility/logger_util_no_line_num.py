import logging


# Copied from https://stackoverflow.com/a/56944256
class LogFormat(logging.Formatter):
    BLUE = {"color": "blue"}
    GREEN = {"color": "green"}
    GREY = {"color": "grey"}
    YELLOW = {"color": "yellow"}
    RED = {"color": "red"}
    BLUE_BOLD = {"color": "blue_bold"}
    GREEN_BOLD = {"color": "green_bold"}
    GREY_BOLD = {"color": "grey_bold"}
    YELLOW_BOLD = {"color": "yellow_bold"}
    RED_BOLD = {"color": "red_bold"}
    BLUE_UNDERLINE = {"color": "blue_underline"}
    GREEN_UNDERLINE = {"color": "green_underline"}
    GREY_UNDERLINE = {"color": "grey_underline"}
    YELLOW_UNDERLINE = {"color": "yellow_underline"}
    RED_UNDERLINE = {"color": "red_underline"}

    """Logging Formatter to add colors and count warning / errors"""
    colors = {
        "blue": "\x1b[34m",
        "green": "\x1b[32m",
        "grey": "\x1b[37m",
        "yellow": "\x1b[33m",
        "red": "\x1b[31m",
        "blue_bold": "\x1b[34;1m",
        "green_bold": "\x1b[32;1m",
        "grey_bold": "\x1b[37;1m",
        "yellow_bold": "\x1b[33;1m",
        "red_bold": "\x1b[31;1m",
        "blue_underline": "\x1b[34;21m",
        "green_underline": "\x1b[32;21m",
        "grey_underline": "\x1b[37;21m",
        "yellow_underline": "\x1b[33;21m",
        "red_underline": "\x1b[31;21m",
        "reset": "\x1b[0m"
    }
    tag_format = "%(asctime)s [%(levelname).1s]: {msg}"
    msg_format = "%(message)s"

    FORMATS = {
        logging.DEBUG: colors["green"] + tag_format + colors["reset"],
        logging.INFO: colors["grey"] + tag_format + colors["reset"],
        logging.WARNING: colors["yellow"] + tag_format + colors["reset"],
        logging.ERROR: colors["red"] + tag_format + colors["reset"],
        logging.CRITICAL: colors["red_underline"] + tag_format + colors["reset"]
    }

    def format(self, record):
        msg_format = self.msg_format
        if "color" in record.__dict__:
            color_value = record.__dict__["color"]
            if color_value in LogFormat.colors:
                msg_format = LogFormat.colors["reset"] + LogFormat.colors[color_value] + msg_format
                # we put reset first because when constructing thre will be no problem
        log_fmt = self.FORMATS.get(record.levelno)
        log_fmt = log_fmt.format(msg=msg_format)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def getlogger_no_line_num(name: str, log_level: int, color=True) -> logging.Logger:
    if not color:
        logging.basicConfig(level=log_level,
                            format='%(asctime)s [%(levelname).1s]: %(message)s')
        logger = logging.getLogger(name)
        return logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(LogFormat())
    logger.addHandler(ch)
    return logger

# logger = getlogger(__name__, logging.DEBUG)
#
#
# logger.debug("Hello", extra=LogFormat.BLUE_UNDERLINE)
# logger.info("info message")
# logger.warning("warning message")
# logger.error("error message")
# logger.critical("critical message")
