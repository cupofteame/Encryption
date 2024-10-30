#include <QApplication>
#include "EncryptionWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    EncryptionWindow window;
    window.show();
    return app.exec();
}
