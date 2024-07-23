# 23.07.2024 10:41:50 Genrated by cbp2cmake V2.5.0 Finale X86 
project(hscrypt LANGUAGES C)
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
set (CMAKE_INSTALL_PREFIX /usr )
add_executable(hscrypt tools.c cmdline.c hscrypt.c)
install(TARGETS hscrypt RUNTIME DESTINATION bin)
