# -*- coding: utf-8 -*-
'''
fortify.fpr
~~~~~~~~~~~

'''
from .utils import openfpr


class FPR(object):
    def __init__(self, project, **kwargs):
        if isinstance(project, basestring):
            self._project = project = openfpr(project)
        elif isinstance(package, dict):
            self._project = project
        else:
            raise TypeError

        self.FVDL = project['audit.fvdl'].getroot()
        self.Audit = project['audit.xml'].getroot()
        self.FilterTemplate = project['filtertemplate.xml'].getroot()
