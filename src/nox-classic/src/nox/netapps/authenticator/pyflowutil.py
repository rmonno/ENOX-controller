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
            fp, pathname, description = imp.find_module('_pyflowutil', [dirname(__file__)])
        except ImportError:
            import _pyflowutil
            return _pyflowutil
        if fp is not None:
            try:
                _mod = imp.load_module('_pyflowutil', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _pyflowutil = swig_import_helper()
    del swig_import_helper
else:
    import _pyflowutil
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


class imaxdiv_t(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, imaxdiv_t, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, imaxdiv_t, name)
    __repr__ = _swig_repr
    __swig_setmethods__["quot"] = _pyflowutil.imaxdiv_t_quot_set
    __swig_getmethods__["quot"] = _pyflowutil.imaxdiv_t_quot_get
    if _newclass:quot = _swig_property(_pyflowutil.imaxdiv_t_quot_get, _pyflowutil.imaxdiv_t_quot_set)
    __swig_setmethods__["rem"] = _pyflowutil.imaxdiv_t_rem_set
    __swig_getmethods__["rem"] = _pyflowutil.imaxdiv_t_rem_get
    if _newclass:rem = _swig_property(_pyflowutil.imaxdiv_t_rem_get, _pyflowutil.imaxdiv_t_rem_set)
    def __init__(self): 
        this = _pyflowutil.new_imaxdiv_t()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _pyflowutil.delete_imaxdiv_t
    __del__ = lambda self : None;
imaxdiv_t_swigregister = _pyflowutil.imaxdiv_t_swigregister
imaxdiv_t_swigregister(imaxdiv_t)


def imaxabs(*args):
  return _pyflowutil.imaxabs(*args)
imaxabs = _pyflowutil.imaxabs

def imaxdiv(*args):
  return _pyflowutil.imaxdiv(*args)
imaxdiv = _pyflowutil.imaxdiv

def strtoimax(*args):
  return _pyflowutil.strtoimax(*args)
strtoimax = _pyflowutil.strtoimax

def strtoumax(*args):
  return _pyflowutil.strtoumax(*args)
strtoumax = _pyflowutil.strtoumax

def wcstoimax(*args):
  return _pyflowutil.wcstoimax(*args)
wcstoimax = _pyflowutil.wcstoimax

def wcstoumax(*args):
  return _pyflowutil.wcstoumax(*args)
wcstoumax = _pyflowutil.wcstoumax

def exit(*args):
  return _pyflowutil.exit(*args)
exit = _pyflowutil.exit
import nox.lib.netinet
class Flow_in_event(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, Flow_in_event, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, Flow_in_event, name)
    __repr__ = _swig_repr
    def __init__(self): 
        this = _pyflowutil.new_Flow_in_event()
        try: self.this.append(this)
        except: self.this = this
    __swig_getmethods__["static_get_name"] = lambda x: _pyflowutil.Flow_in_event_static_get_name
    if _newclass:static_get_name = staticmethod(_pyflowutil.Flow_in_event_static_get_name)
    __swig_getmethods__["fill_python_event"] = lambda x: _pyflowutil.Flow_in_event_fill_python_event
    if _newclass:fill_python_event = staticmethod(_pyflowutil.Flow_in_event_fill_python_event)
    __swig_getmethods__["register_event_converter"] = lambda x: _pyflowutil.Flow_in_event_register_event_converter
    if _newclass:register_event_converter = staticmethod(_pyflowutil.Flow_in_event_register_event_converter)
    __swig_destroy__ = _pyflowutil.delete_Flow_in_event
    __del__ = lambda self : None;
Flow_in_event_swigregister = _pyflowutil.Flow_in_event_swigregister
Flow_in_event_swigregister(Flow_in_event)

def Flow_in_event_static_get_name():
  return _pyflowutil.Flow_in_event_static_get_name()
Flow_in_event_static_get_name = _pyflowutil.Flow_in_event_static_get_name

def Flow_in_event_fill_python_event(*args):
  return _pyflowutil.Flow_in_event_fill_python_event(*args)
Flow_in_event_fill_python_event = _pyflowutil.Flow_in_event_fill_python_event

def Flow_in_event_register_event_converter(*args):
  return _pyflowutil.Flow_in_event_register_event_converter(*args)
Flow_in_event_register_event_converter = _pyflowutil.Flow_in_event_register_event_converter

class Flow_expr(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, Flow_expr, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, Flow_expr, name)
    __repr__ = _swig_repr
    LOCSRC = _pyflowutil.Flow_expr_LOCSRC
    LOCDST = _pyflowutil.Flow_expr_LOCDST
    HSRC = _pyflowutil.Flow_expr_HSRC
    HDST = _pyflowutil.Flow_expr_HDST
    HNETSRC = _pyflowutil.Flow_expr_HNETSRC
    HNETDST = _pyflowutil.Flow_expr_HNETDST
    USRC = _pyflowutil.Flow_expr_USRC
    UDST = _pyflowutil.Flow_expr_UDST
    CONN_ROLE = _pyflowutil.Flow_expr_CONN_ROLE
    GROUPSRC = _pyflowutil.Flow_expr_GROUPSRC
    GROUPDST = _pyflowutil.Flow_expr_GROUPDST
    DLVLAN = _pyflowutil.Flow_expr_DLVLAN
    DLVLANPCP = _pyflowutil.Flow_expr_DLVLANPCP
    DLSRC = _pyflowutil.Flow_expr_DLSRC
    DLDST = _pyflowutil.Flow_expr_DLDST
    DLTYPE = _pyflowutil.Flow_expr_DLTYPE
    NWSRC = _pyflowutil.Flow_expr_NWSRC
    NWDST = _pyflowutil.Flow_expr_NWDST
    NWPROTO = _pyflowutil.Flow_expr_NWPROTO
    TPSRC = _pyflowutil.Flow_expr_TPSRC
    TPDST = _pyflowutil.Flow_expr_TPDST
    SUBNETSRC = _pyflowutil.Flow_expr_SUBNETSRC
    SUBNETDST = _pyflowutil.Flow_expr_SUBNETDST
    FUNC = _pyflowutil.Flow_expr_FUNC
    MAX_PRED = _pyflowutil.Flow_expr_MAX_PRED
    REQUEST = _pyflowutil.Flow_expr_REQUEST
    RESPONSE = _pyflowutil.Flow_expr_RESPONSE
    ALWAYS_APPLY = _pyflowutil.Flow_expr_ALWAYS_APPLY
    APPLY_AT_SOURCE = _pyflowutil.Flow_expr_APPLY_AT_SOURCE
    APPLY_AT_DESTINATION = _pyflowutil.Flow_expr_APPLY_AT_DESTINATION
    def __init__(self, *args): 
        this = _pyflowutil.new_Flow_expr(*args)
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _pyflowutil.delete_Flow_expr
    __del__ = lambda self : None;
    def set_fn(self, *args): return _pyflowutil.Flow_expr_set_fn(self, *args)
    def set_pred(self, *args): return _pyflowutil.Flow_expr_set_pred(self, *args)
    __swig_setmethods__["apply_side"] = _pyflowutil.Flow_expr_apply_side_set
    __swig_getmethods__["apply_side"] = _pyflowutil.Flow_expr_apply_side_get
    if _newclass:apply_side = _swig_property(_pyflowutil.Flow_expr_apply_side_get, _pyflowutil.Flow_expr_apply_side_set)
    __swig_setmethods__["global_id"] = _pyflowutil.Flow_expr_global_id_set
    __swig_getmethods__["global_id"] = _pyflowutil.Flow_expr_global_id_get
    if _newclass:global_id = _swig_property(_pyflowutil.Flow_expr_global_id_get, _pyflowutil.Flow_expr_global_id_set)
Flow_expr_swigregister = _pyflowutil.Flow_expr_swigregister
Flow_expr_swigregister(Flow_expr)

class Flow_action(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, Flow_action, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, Flow_action, name)
    __repr__ = _swig_repr
    ALLOW = _pyflowutil.Flow_action_ALLOW
    DENY = _pyflowutil.Flow_action_DENY
    WAYPOINT = _pyflowutil.Flow_action_WAYPOINT
    C_FUNC = _pyflowutil.Flow_action_C_FUNC
    PY_FUNC = _pyflowutil.Flow_action_PY_FUNC
    NAT = _pyflowutil.Flow_action_NAT
    MAX_ACTIONS = _pyflowutil.Flow_action_MAX_ACTIONS
    def __init__(self, *args): 
        this = _pyflowutil.new_Flow_action(*args)
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _pyflowutil.delete_Flow_action
    __del__ = lambda self : None;
    def set_arg(self, *args): return _pyflowutil.Flow_action_set_arg(self, *args)
Flow_action_swigregister = _pyflowutil.Flow_action_swigregister
Flow_action_swigregister(Flow_action)

class strlist(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, strlist, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, strlist, name)
    __repr__ = _swig_repr
    def iterator(self): return _pyflowutil.strlist_iterator(self)
    def __iter__(self): return self.iterator()
    def __nonzero__(self): return _pyflowutil.strlist___nonzero__(self)
    def __bool__(self): return _pyflowutil.strlist___bool__(self)
    def __len__(self): return _pyflowutil.strlist___len__(self)
    def pop(self): return _pyflowutil.strlist_pop(self)
    def __getslice__(self, *args): return _pyflowutil.strlist___getslice__(self, *args)
    def __setslice__(self, *args): return _pyflowutil.strlist___setslice__(self, *args)
    def __delslice__(self, *args): return _pyflowutil.strlist___delslice__(self, *args)
    def __delitem__(self, *args): return _pyflowutil.strlist___delitem__(self, *args)
    def __getitem__(self, *args): return _pyflowutil.strlist___getitem__(self, *args)
    def __setitem__(self, *args): return _pyflowutil.strlist___setitem__(self, *args)
    def append(self, *args): return _pyflowutil.strlist_append(self, *args)
    def empty(self): return _pyflowutil.strlist_empty(self)
    def size(self): return _pyflowutil.strlist_size(self)
    def clear(self): return _pyflowutil.strlist_clear(self)
    def swap(self, *args): return _pyflowutil.strlist_swap(self, *args)
    def get_allocator(self): return _pyflowutil.strlist_get_allocator(self)
    def begin(self): return _pyflowutil.strlist_begin(self)
    def end(self): return _pyflowutil.strlist_end(self)
    def rbegin(self): return _pyflowutil.strlist_rbegin(self)
    def rend(self): return _pyflowutil.strlist_rend(self)
    def pop_back(self): return _pyflowutil.strlist_pop_back(self)
    def erase(self, *args): return _pyflowutil.strlist_erase(self, *args)
    def __init__(self, *args): 
        this = _pyflowutil.new_strlist(*args)
        try: self.this.append(this)
        except: self.this = this
    def push_back(self, *args): return _pyflowutil.strlist_push_back(self, *args)
    def front(self): return _pyflowutil.strlist_front(self)
    def back(self): return _pyflowutil.strlist_back(self)
    def assign(self, *args): return _pyflowutil.strlist_assign(self, *args)
    def resize(self, *args): return _pyflowutil.strlist_resize(self, *args)
    def insert(self, *args): return _pyflowutil.strlist_insert(self, *args)
    def pop_front(self): return _pyflowutil.strlist_pop_front(self)
    def push_front(self, *args): return _pyflowutil.strlist_push_front(self, *args)
    def reverse(self): return _pyflowutil.strlist_reverse(self)
    __swig_destroy__ = _pyflowutil.delete_strlist
    __del__ = lambda self : None;
strlist_swigregister = _pyflowutil.strlist_swigregister
strlist_swigregister(strlist)

PYFLOW_UTIL_HH = _pyflowutil.PYFLOW_UTIL_HH
class PyFlow_util(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, PyFlow_util, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, PyFlow_util, name)
    __repr__ = _swig_repr
    def __init__(self, *args): 
        this = _pyflowutil.new_PyFlow_util(*args)
        try: self.this.append(this)
        except: self.this = this
    def configure(self, *args): return _pyflowutil.PyFlow_util_configure(self, *args)
    def valid_fn_args(self, *args): return _pyflowutil.PyFlow_util_valid_fn_args(self, *args)
    def set_action_argument(self, *args): return _pyflowutil.PyFlow_util_set_action_argument(self, *args)
    __swig_destroy__ = _pyflowutil.delete_PyFlow_util
    __del__ = lambda self : None;
PyFlow_util_swigregister = _pyflowutil.PyFlow_util_swigregister
PyFlow_util_swigregister(PyFlow_util)

from nox.lib.core import Component

class PyFlowUtil(Component):
    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.flowutil = PyFlow_util(ctxt)
    
    def configure(self, configuration):
        self.flowutil.configure(configuration)
        Flow_in_event.register_event_converter(self.ctxt)

    def getInterface(self):
        return str(PyFlowUtil)

    def valid_fn_args(self, key, args):
        return self.flowutil.valid_fn_args(key, args)

    def set_action_argument(self, action, arg, fn_args):
        return self.flowutil.set_action_argument(action, arg, fn_args)

def getFactory():
    class Factory():
        def instance(self, context):
            return PyFlowUtil(context)

    return Factory()



