# This file was automatically generated by SWIG (http://www.swig.org).
# Version 1.3.40
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.
# This file is compatible with both classic and new-style classes.

from sys import version_info
if version_info >= (2,6,0):
    def swig_import_helper():
        from os.path import dirname
        import imp
        fp = None
        try:
            fp, pathname, description = imp.find_module('_pysimple_cc_py_app', [dirname(__file__)])
        except ImportError:
            import _pysimple_cc_py_app
            return _pysimple_cc_py_app
        if fp is not None:
            try:
                _mod = imp.load_module('_pysimple_cc_py_app', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _pysimple_cc_py_app = swig_import_helper()
    del swig_import_helper
else:
    import _pysimple_cc_py_app
del version_info
try:
    _swig_property = property
except NameError:
    pass # Python < 2.2 doesn't have 'property'.
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'SwigPyObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError(name)

def _swig_repr(self):
    try: strthis = "proxy of " + self.this.__repr__()
    except: strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

try:
    _object = object
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0


class simple_cc_py_proxy(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, simple_cc_py_proxy, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, simple_cc_py_proxy, name)
    __repr__ = _swig_repr
    def __init__(self, *args): 
        this = _pysimple_cc_py_app.new_simple_cc_py_proxy(*args)
        try: self.this.append(this)
        except: self.this = this
    def configure(self, *args): return _pysimple_cc_py_app.simple_cc_py_proxy_configure(self, *args)
    def install(self, *args): return _pysimple_cc_py_app.simple_cc_py_proxy_install(self, *args)
    __swig_destroy__ = _pysimple_cc_py_app.delete_simple_cc_py_proxy
    __del__ = lambda self : None;
simple_cc_py_proxy_swigregister = _pysimple_cc_py_app.simple_cc_py_proxy_swigregister
simple_cc_py_proxy_swigregister(simple_cc_py_proxy)

from nox.lib.core import Component

  class pysimple_cc_py_app(Component):
    """
      An adaptor over the C++ based Python bindings to
      simplify their implementation.
    """  
    def __init__(self, ctxt):
      self.pscpa = simple_cc_py_proxy(ctxt)

    def configure(self, configuration):
      self.pscpa.configure(configuration)

    def install(self):
      pass

    def getInterface(self):
      return str(pysimple_cc_py_app)

    # --
    # Expose additional methods here!
    # --


def getFactory():
      class Factory():
          def instance(self, context):
                      
              return pysimple_cc_py_app(context)

      return Factory()



