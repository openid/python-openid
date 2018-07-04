"""Utilities for key-value format conversions."""
from __future__ import unicode_literals

import logging

import six

from .oidutil import string_to_text

__all__ = ['seqToKV', 'kvToSeq', 'dictToKV', 'kvToDict']


_LOGGER = logging.getLogger(__name__)


class KVFormError(ValueError):
    pass


def seqToKV(seq, strict=False):
    """Represent a sequence of pairs of strings as newline-terminated
    key:value pairs. The pairs are generated in the order given.

    @param seq: The pairs
    @type seq: List[Tuple[six.text_type, six.text_type]], binary_type values are deprecated.

    @return: A string representation of the sequence
    @rtype: six.text_type
    """
    def err(msg):
        formatted = 'seqToKV warning: %s: %r' % (msg, seq)
        if strict:
            raise KVFormError(formatted)
        else:
            _LOGGER.debug(formatted)

    lines = []
    for k, v in seq:
        if not isinstance(k, (six.text_type, six.binary_type)):
            err('Converting key to text: %r' % k)
            k = six.text_type(k)
        if not isinstance(v, (six.text_type, six.binary_type)):
            err('Converting value to text: %r' % v)
            v = six.text_type(v)

        k = string_to_text(k, "Binary values for keys are deprecated. Use text input instead.")
        v = string_to_text(v, "Binary values for values are deprecated. Use text input instead.")

        if '\n' in k:
            raise KVFormError(
                'Invalid input for seqToKV: key contains newline: %r' % (k,))

        if ':' in k:
            raise KVFormError(
                'Invalid input for seqToKV: key contains colon: %r' % (k,))

        if k.strip() != k:
            err('Key has whitespace at beginning or end: %r' % (k,))

        if '\n' in v:
            raise KVFormError(
                'Invalid input for seqToKV: value contains newline: %r' % (v,))

        if v.strip() != v:
            err('Value has whitespace at beginning or end: %r' % (v,))

        lines.append(k + ':' + v + '\n')

    return ''.join(lines)


def kvToSeq(data, strict=False):
    """
    Parse newline-terminated key:value pair string into a sequence.

    After one parse, seqToKV and kvToSeq are inverses, with no warnings::

        seq = kvToSeq(s)
        seqToKV(kvToSeq(seq)) == seq

    @type data: six.text_type, six.binary_type is deprecated

    @rtype: List[Tuple[six.text_type, six.text_type]]
    """
    def err(msg):
        formatted = 'kvToSeq warning: %s: %r' % (msg, data)
        if strict:
            raise KVFormError(formatted)
        else:
            _LOGGER.debug(formatted)

    data = string_to_text(data, "Binary values for data are deprecated. Use text input instead.")

    lines = data.split('\n')
    if lines[-1]:
        err('Does not end in a newline')
    else:
        del lines[-1]

    pairs = []
    line_num = 0
    for line in lines:
        line_num += 1

        # Ignore blank lines
        if not line.strip():
            continue

        pair = line.split(':', 1)
        if len(pair) == 2:
            k, v = pair
            k_s = k.strip()
            if k_s != k:
                fmt = ('In line %d, ignoring leading or trailing '
                       'whitespace in key %r')
                err(fmt % (line_num, k))

            if not k_s:
                err('In line %d, got empty key' % (line_num,))

            v_s = v.strip()
            if v_s != v:
                fmt = ('In line %d, ignoring leading or trailing '
                       'whitespace in value %r')
                err(fmt % (line_num, v))

            pairs.append((k_s, v_s))
        else:
            err('Line %d does not contain a colon' % line_num)

    return pairs


def dictToKV(d):
    seq = sorted(d.items())
    return seqToKV(seq)


def kvToDict(s):
    return dict(kvToSeq(s))
