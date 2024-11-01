#ifndef ENCRYPTION_ENCRYPTIONWINDOW_H
#define ENCRYPTION_ENCRYPTIONWINDOW_H

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressBar>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QComboBox>

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

    // Common widgets
    QProgressBar *progressBar;
    QComboBox *encryptionStrength;

    // Helper functions
    void setupUI();
    void setupEncryptionTab(QWidget *tab);
    void setupDecryptionTab(QWidget *tab);
    void processFile(bool encrypting, const QString &key, const QString &inputFile, 
                    const QString &outputDir);
    void secureDelete(const QString &filePath);
    QString calculateFileHash(const QString &filePath);
    void createBackup(const QString &filePath);
    void updateProgress(int value);
};

#endif //ENCRYPTION_ENCRYPTIONWINDOW_H 