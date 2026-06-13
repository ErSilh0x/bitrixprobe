
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"

def green(text):
    return f"{Colors.GREEN}{text}{Colors.RESET}"

def red(text):
    return f"{Colors.RED}{text}{Colors.RESET}"

def yellow(text):
    return f"{Colors.YELLOW}{text}{Colors.RESET}"

def blue(text):
    return f"{Colors.BLUE}{text}{Colors.RESET}"

def cyan(text):
    return f"{Colors.CYAN}{text}{Colors.RESET}"

def bold(text):
    return f"{Colors.BOLD}{text}{Colors.RESET}"

def red_badge(text):
    """
    Return text highlighted as a red terminal badge.
    """

    red_background = "\033[41m"
    white_bold_text = "\033[1;30m"
    reset = "\033[0m"

    return f"{white_bold_text}{red_background} {text} {reset}"

def error_message(text):
    return f"{red('[!] Error:')} {text}"

def hint_message(text):
    return f"{yellow('[*] Hint:')} {text}"