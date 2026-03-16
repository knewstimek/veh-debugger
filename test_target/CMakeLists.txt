add_executable(test_target main.cpp)
target_compile_definitions(test_target PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
)
