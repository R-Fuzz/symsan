configure_file(lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
  @ONLY)

# lit takes the path to run from the *build* tree and walks up from it looking
# for the config, so running one suite on its own -- "lit tests/symsan", which
# is what CI does -- needs that directory to exist here even though every test
# in it lives in the source tree.
foreach(suite symsan fuzzing)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${suite})
endforeach()

