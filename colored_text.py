
RESET = '\033[0m'
BOLD = '\033[1m'

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
PINK = '\033[38;5;205m'


def red(text):
    return f'{RED}{text}{RESET}'


def green(text):
    return f'{GREEN}{text}{RESET}'


def yellow(text):
    return f'{YELLOW}{text}{RESET}'


def blue(text):
    return f'{BLUE}{text}{RESET}'


def cyan(text):
    return f'{CYAN}{text}{RESET}'


def bold(text):
    return f'{BOLD}{text}{RESET}'

def pink(text):
    return f'{PINK}{text}{RESET}'


def bold_green(text):
    return f'{BOLD}{GREEN}{text}{RESET}'


def bold_red(text):
    return f'{BOLD}{RED}{text}{RESET}'


def bold_yellow(text):
    return f'{BOLD}{YELLOW}{text}{RESET}'


def bold_blue(text):
    return f'{BOLD}{BLUE}{text}{RESET}'


def bold_cyan(text):
    return f'{BOLD}{CYAN}{text}{RESET}'
