# -*- coding: utf-8 -*-
'''
fortify.fvdl
~~~~~~~~~~~~

'''
from lxml.objectify import ObjectPath
from lxml import etree, objectify


FVDLParser = objectify.makeparser(remove_blank_text=True,
                                  resolve_entities=False)

FVDLParser.set_element_class_lookup(
    etree.ElementNamespaceClassLookup(
        objectify.ObjectifyElementClassLookup()))

def parse(source, **kwargs):
    return objectify.parse(source, parser=FVDLParser, **kwargs)

