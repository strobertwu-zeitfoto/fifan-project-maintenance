"""Verify explicit byte bindings, never a report's own acceptance claims."""
from __future__ import annotations

import hashlib
import re
from ..models import Context, Finding


def run(ctx: Context) -> list[Finding]:
    out = []
    bindings = ctx.config.get('evidence_bindings', [])
    if not isinstance(bindings, list):
        return [Finding('evidence', 'invalid_binding', 'evidence_bindings 必须为列表')]
    for item in bindings:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) for k in ('report', 'candidate', 'sha256')) or not re.fullmatch(r'[a-fA-F0-9]{64}', item.get('sha256', '')):
            out.append(Finding('evidence', 'invalid_binding', '证据绑定须含 report、candidate 与 64 位 SHA256'))
            continue
        try:
            # Reading proves both originals are available under the active scope.
            ctx.read_bytes(item['report'])
            digest = hashlib.sha256(ctx.read_bytes(item['candidate'])).hexdigest()
            if digest != item['sha256'].lower():
                out.append(Finding('evidence', 'candidate_mismatch', '候选原件与声明指纹不匹配', item['candidate'], evidence={'report': item['report']}))
            else:
                out.append(Finding('evidence', 'binding_verified', '原件指纹绑定已核实；不代表运行或用户验收', item['candidate'], status='Passed', severity='info', evidence={'report': item['report'], 'sha256': digest}))
        except (OSError, ValueError) as exc:
            out.append(Finding('evidence', 'original_unavailable', '证据原件缺失、越界或超出读取限制', item['candidate'], status='Unknown', evidence={'error': type(exc).__name__}))
    return out
