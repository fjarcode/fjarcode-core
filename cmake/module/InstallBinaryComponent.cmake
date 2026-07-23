# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)
include(GNUInstallDirs)

function(install_binary_component component)
  cmake_parse_arguments(PARSE_ARGV 1
    IC                          # prefix
    "HAS_MANPAGE;INTERNAL"      # options
    ""                          # one_value_keywords
    "ALIASES"                   # multi_value_keywords
  )
  set(target_name ${component})
  get_target_property(output_name ${target_name} OUTPUT_NAME)
  if(NOT output_name)
    set(output_name ${target_name})
  endif()
  if(IC_INTERNAL)
    set(runtime_dest ${CMAKE_INSTALL_LIBEXECDIR})
  else()
    set(runtime_dest ${CMAKE_INSTALL_BINDIR})
  endif()
  install(TARGETS ${target_name}
    RUNTIME DESTINATION ${runtime_dest}
    COMPONENT ${component}
  )
  if(BUILD_BINARY_ALIASES)
    foreach(alias_name IN LISTS IC_ALIASES)
      install(PROGRAMS $<TARGET_FILE:${target_name}>
        DESTINATION ${runtime_dest}
        RENAME ${alias_name}${CMAKE_EXECUTABLE_SUFFIX}
        COMPONENT ${component}
      )
    endforeach()
  endif()
  if(INSTALL_MAN AND IC_HAS_MANPAGE)
    if(EXISTS ${PROJECT_SOURCE_DIR}/doc/man/${output_name}.1)
      install(FILES ${PROJECT_SOURCE_DIR}/doc/man/${output_name}.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
        COMPONENT ${component}
      )
      if(BUILD_BINARY_ALIASES)
        foreach(alias_name IN LISTS IC_ALIASES)
          install(FILES ${PROJECT_SOURCE_DIR}/doc/man/${output_name}.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
            RENAME ${alias_name}.1
            COMPONENT ${component}
          )
        endforeach()
      endif()
    elseif(EXISTS ${PROJECT_SOURCE_DIR}/doc/man/${target_name}.1)
      install(FILES ${PROJECT_SOURCE_DIR}/doc/man/${target_name}.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
        RENAME ${output_name}.1
        COMPONENT ${component}
      )
      if(BUILD_BINARY_ALIASES)
        foreach(alias_name IN LISTS IC_ALIASES)
          install(FILES ${PROJECT_SOURCE_DIR}/doc/man/${target_name}.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
            RENAME ${alias_name}.1
            COMPONENT ${component}
          )
        endforeach()
      endif()
    endif()
  endif()
endfunction()
