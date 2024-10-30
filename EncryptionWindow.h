#ifndef ENCRYPTION_ENCRYPTIONWINDOW_H
#define ENCRYPTION_ENCRYPTIONWINDOW_H

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QTabWidget>

class EncryptionWindow : public QMainWindow {
Q_OBJECT

public:
    explicit EncryptionWindow(QWidget *parent = nullptr);

private slots:
    void selectEncryptInputFile();
    void selectEncryptOutputDir();
    void selectDecryptInputFile();
    void selectDecryptOutputDir();
    void encryptFile();
    void decryptFile();

private:
    // Encryption tab widgets
    QLineEdit *encryptKeyInput;
    QLineEdit *encryptInputFileEdit;
    QLineEdit *encryptOutputDirEdit;
    QPushButton *encryptInputBrowseButton;
    QPushButton *encryptOutputBrowseButton;
    QPushButton *encryptButton;

    // Decryption tab widgets
    QLineEdit *decryptKeyInput;
    QLineEdit *decryptInputFileEdit;
    QLineEdit *decryptOutputDirEdit;
    QPushButton *decryptInputBrowseButton;
    QPushButton *decryptOutputBrowseButton;
    QPushButton *decryptButton;

    void setupUI();
    void setupEncryptionTab(QWidget *tab);
    void setupDecryptionTab(QWidget *tab);
    void processFile(bool encrypting, const QString &key, const QString &inputFile, 
                    const QString &outputDir);
};

#endif //ENCRYPTION_ENCRYPTIONWINDOW_H 