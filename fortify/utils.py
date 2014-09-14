# -*- coding: utf-8 -*-
'''
fortify.utils
~~~~~~~~~~~~~

'''
from lxml import objectify
from zipfile import ZipFile
import logging

from .fvdl import AuditParser, FilterTemplateParser, FVDLParser


XML_PARSERS = {
    'audit.fvdl': FVDLParser,
    'audit.xml': AuditParser,
    'filtertemplate.xml': FilterTemplateParser,
}


def openfpr(fprfile):
    '''
    Read and parse important files from an FPR.

    :param fprfile: Path to the FPR file, or a file-like object.
    :returns: A dict of :class:`lxml.etree._ElementTree` objects.
    '''

    zfpr = fprfile

    if not isinstance(fprfile, ZipFile):
        zfpr = ZipFile(fprfile)

    pkg = {}

    for filename in (f for f in zfpr.namelist() if f in XML_PARSERS):
        parser = XML_PARSERS.get(filename)
        artifact = zfpr.open(filename)
        logging.debug("Parsing %s w/parser %r", filename, parser)
        pkg[filename] = objectify.parse(artifact, parser=parser)

    return pkg
