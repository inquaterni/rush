//
// Created by inquaterni on 2/24/26.
//

#ifndef GLOBAL_H
#define GLOBAL_H

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    #define RUSH_EXCEPTIONS_ENABLED 1
#else
    #define RUSH_EXCEPTIONS_ENABLED 0
#endif

#endif //GLOBAL_H
