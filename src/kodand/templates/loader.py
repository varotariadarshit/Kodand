import logging
from pathlib import Path

import yaml

from kodand.templates.models import KodandTemplate
from kodand.templates.regexguard import validate_pattern

log = logging.getLogger(__name__)


def load_templates(template_root: Path):
    templates = []
    for file in template_root.rglob("*.yaml"):
        try:
            data = yaml.safe_load(file.read_text())
            template = KodandTemplate.model_validate(data)
            # reject catastrophic regex at load time (ReDoS guard, part 1)
            safe = []
            for rx in template.detection.regex:
                ok, msg = validate_pattern(rx)
                if ok: safe.append(rx)
                else: log.warning("Skipping unsafe regex in %s: %s", template.id, msg)
            template.detection.regex = safe
            templates.append(template)
        except Exception as exc:
            log.warning("Failed to load template %s: %s", file, exc)
    return templates
