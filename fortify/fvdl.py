# -*- coding: utf-8 -*-
'''
fortify.fvdl
~~~~~~~~~~~~

'''
from lxml.etree import AttributeBasedElementClassLookup, \
    ElementNamespaceClassLookup
from lxml.objectify import ElementMaker, ObjectifiedDataElement, \
    ObjectifyElementClassLookup
from lxml import objectify
from dateutil import tz
import arrow
import datetime
import dateutil.parser
import uuid


AuditParser = objectify.makeparser(ns_clean=True,
                                   remove_blank_text=True,
                                   resolve_entities=False,
                                   strip_cdata=False)

FilterTemplateParser = objectify.makeparser(ns_clean=True,
                                            remove_blank_text=True,
                                            resolve_entities=False,
                                            strip_cdata=False)

FVDLParser = objectify.makeparser(ns_clean=True,
                                  remove_blank_text=True,
                                  resolve_entities=False,
                                  strip_cdata=False)

AuditObjectifiedElementNamespaceClassLookup = ElementNamespaceClassLookup(
    ObjectifyElementClassLookup())

FVDLObjectifiedElementNamespaceClassLookup = ElementNamespaceClassLookup(
    ObjectifyElementClassLookup())


class FVDLElement(ObjectifiedDataElement):
    def get_vulnerablities(self):
        return self.Vulnerabilities.Vulnerability


class DateTimeElement(ObjectifiedDataElement):
    @property
    def date(self):
        return self.datetime.date()

    @property
    def time(self):
        return self.datetime.time()

    @property
    def datetime(self):
        try:
            return arrow.get(str(self))
        except arrow.parser.ParserError:
            return arrow.get(dateutil.parser.parse(str(self)))


class TimeStampElement(ObjectifiedDataElement):
    @property
    def date(self):
        return datetime.date(*map(int, self.get('date').split('-')))

    @property
    def time(self):
        return datetime.time(*map(int, self.get('time').split(':')))

    @property
    def datetime(self):
        return arrow.get(
            datetime.datetime.combine(self.date, self.time),
            tzinfo=tz.tzlocal()) # use local timezone


class UUIDElement(ObjectifiedDataElement):
    @property
    def uuid(self):
        return uuid.UUID(str(self))


class VulnerabilityElement(ObjectifiedDataElement):
    @property
    def InstanceID(self):
        return self.InstanceInfo.InstanceID


AUDIT_NAMESPACE = AuditObjectifiedElementNamespaceClassLookup.get_namespace(
    'xmlns://www.fortify.com/schema/audit')

FVDL_NAMESPACE = FVDLObjectifiedElementNamespaceClassLookup.get_namespace(
    'xmlns://www.fortifysoftware.com/schema/fvdl')

AUDIT_NAMESPACE['CreationDate'] = DateTimeElement
AUDIT_NAMESPACE['EditTime'] = DateTimeElement
AUDIT_NAMESPACE['RemoveScanDate'] = DateTimeElement
AUDIT_NAMESPACE['Timestamp'] = DateTimeElement
AUDIT_NAMESPACE['WriteDate'] = DateTimeElement

FVDL_NAMESPACE['BeginTS'] = TimeStampElement
FVDL_NAMESPACE['CreatedTS'] = TimeStampElement
FVDL_NAMESPACE['EndTS'] = TimeStampElement
FVDL_NAMESPACE['FVDL'] = FVDLElement
FVDL_NAMESPACE['FirstEventTimestamp'] = TimeStampElement
FVDL_NAMESPACE['ModifiedTS'] = TimeStampElement
FVDL_NAMESPACE['UUID'] = UUIDElement
FVDL_NAMESPACE['Vulnerability'] = VulnerabilityElement

AuditParser.set_element_class_lookup(
    AuditObjectifiedElementNamespaceClassLookup)

FVDLParser.set_element_class_lookup(
    FVDLObjectifiedElementNamespaceClassLookup)

FVDL = ElementMaker(
    annotate=False,
    namespace='xmlns://www.fortifysoftware.com/schema/FVDL',
    nsmap={
        None: 'xmlns://www.fortifysoftware.com/schema/FVDL',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
        }
    )

Audit = ElementMaker(
    annotate=False,
    namespace='',
    nsmap={
        None: 'xmlns://www.fortify.com/schema/AUDIT',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
        }
    )


def parse(source, **kwargs):
    return objectify.parse(source, parser=FVDLParser, **kwargs)
