#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
#

class Factory(object):
    def __init__(self, klass):
        assert(klass is not None)

        self.__objects = [ ]
        self.__klass   = klass
        print("Factory initialized for '%s' class" % str(klass))

    def objects(self):
        return self.__objects

    def create(self, *args):
        print("Factory is going to create an object (parms = '%s')" %
                  str(args))
        obj = self.__klass(*args)
        assert(obj is not None)

        print("Object '%s' created" % str(obj))
        return obj

if __name__ == '__main__':
    pass
