cmake_minimum_required(VERSION 3.29)
project(encryption)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Set Qt path
set(CMAKE_PREFIX_PATH "C:/Qt/6.8.0/mingw_64")
set(QT_DIR "C:/Qt/6.8.0/mingw_64")

find_package(Qt6 REQUIRED COMPONENTS
    Core
    Gui
    Widgets
)

add_executable(encryption main.cpp EncryptionWindow.cpp EncryptionWindow.h)

target_link_libraries(encryption PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

# Copy Qt DLLs and plugins to output directory
add_custom_command(TARGET encryption POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:encryption>/platforms"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${QT_DIR}/bin/Qt6Core.dll"
        "${QT_DIR}/bin/Qt6Gui.dll"
        "${QT_DIR}/bin/Qt6Widgets.dll"
        "${QT_DIR}/plugins/platforms/qwindows.dll"
        "$<TARGET_FILE_DIR:encryption>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${QT_DIR}/plugins/platforms/qwindows.dll"
        "$<TARGET_FILE_DIR:encryption>/platforms/"
)
