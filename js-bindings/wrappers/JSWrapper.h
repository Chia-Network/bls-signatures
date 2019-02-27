//
// Created by anton on 27.02.19.
//

#ifndef BLS_ABSTRACTWRAPPER_H
#define BLS_ABSTRACTWRAPPER_H

namespace js_wrappers {
    template <class T>
    class JSWrapper {
    public:
        inline explicit JSWrapper(T &wrappedInstance) : wrapped(wrappedInstance) {};
        inline T GetWrappedInstance() const {
            return wrapped;
        };
    protected:
        T wrapped;
    };
}

#endif //BLS_ABSTRACTWRAPPER_H
