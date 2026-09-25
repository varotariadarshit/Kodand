import re

NOTE_ID = re.compile(r"^note-(\d+)$")


def parse_id(value):
    match = NOTE_ID.match(value)
    return int(match.group(1)) if match else None
