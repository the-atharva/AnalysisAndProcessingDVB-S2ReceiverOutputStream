function(target_set_warnings TARGET)
    set(WARNINGS
        -Wall
        -Wextra
        -Wpedantic)
    target_compile_options(${TARGET} PRIVATE ${WARNINGS})
    message(STATUS ${WARNINGS})
endfunction(target_set_warnings)
