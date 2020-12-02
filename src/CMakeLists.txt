AUX_SOURCE_DIRECTORY(utils utilsSRC)
AUX_SOURCE_DIRECTORY(stm stmSRC)
AUX_SOURCE_DIRECTORY(parsers parsersSRC)
AUX_SOURCE_DIRECTORY(myProtocol mpSRC)

add_executable(socks5d main.c
                    socks5_server.c
                    ${utilsSRC}
                    ${stmSRC}
                    ${parsersSRC}
                    ${mpSRC} config.c)

target_link_libraries(socks5d pthread)