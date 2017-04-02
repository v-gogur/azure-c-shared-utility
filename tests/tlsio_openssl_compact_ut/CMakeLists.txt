#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

#this is CMakeLists.txt for <myTestName>_ut
cmake_minimum_required(VERSION 2.8.11)

compileAsC11()
set(theseTestsName tlsio_openssl_compact_ut)

set(${theseTestsName}_test_files
${theseTestsName}.c
)

set(${theseTestsName}_c_files
../../adapters/tlsio_openssl_compact.c
)

set(${theseTestsName}_h_files
callbacks.h
ssl_errors.h
test_points.h
)

include_directories(.)

build_c_test_artifacts(${theseTestsName} ON "tests/azure_c_shared_utility_tests")
