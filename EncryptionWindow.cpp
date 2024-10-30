#include "EncryptionWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QTabWidget>
#include <QFile>
#include <QDir>
#include <fstream>
#include <vector>

EncryptionWindow::EncryptionWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
    setWindowTitle("File Encryptor/Decryptor");
    setMinimumSize(600, 300);
}

void EncryptionWindow::setupUI() {
    auto *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    auto *layout = new QVBoxLayout(centralWidget);
    auto *tabWidget = new QTabWidget(this);
    
    // Create tabs
    auto *encryptTab = new QWidget();
    auto *decryptTab = new QWidget();
    
    setupEncryptionTab(encryptTab);
    setupDecryptionTab(decryptTab);
    
    tabWidget->addTab(encryptTab, "Encrypt");
    tabWidget->addTab(decryptTab, "Decrypt");
    
    layout->addWidget(tabWidget);
}

void EncryptionWindow::setupEncryptionTab(QWidget *tab) {
    auto *layout = new QGridLayout(tab);
    
    // Key input
    auto *keyLabel = new QLabel("Encryption Key:", tab);
    encryptKeyInput = new QLineEdit(tab);
    encryptKeyInput->setEchoMode(QLineEdit::Password);
    layout->addWidget(keyLabel, 0, 0);
    layout->addWidget(encryptKeyInput, 0, 1, 1, 2);
    
    // Input file
    auto *inputLabel = new QLabel("Select File to Encrypt:", tab);
    encryptInputFileEdit = new QLineEdit(tab);
    encryptInputBrowseButton = new QPushButton("Browse", tab);
    layout->addWidget(inputLabel, 1, 0);
    layout->addWidget(encryptInputFileEdit, 1, 1);
    layout->addWidget(encryptInputBrowseButton, 1, 2);
    
    // Output directory
    auto *outputLabel = new QLabel("Save Encrypted File in:", tab);
    encryptOutputDirEdit = new QLineEdit(tab);
    encryptOutputBrowseButton = new QPushButton("Browse", tab);
    layout->addWidget(outputLabel, 2, 0);
    layout->addWidget(encryptOutputDirEdit, 2, 1);
    layout->addWidget(encryptOutputBrowseButton, 2, 2);
    
    // Encrypt button
    encryptButton = new QPushButton("Encrypt File", tab);
    layout->addWidget(encryptButton, 3, 0, 1, 3);
    
    // Connect signals
    connect(encryptInputBrowseButton, &QPushButton::clicked, this, &EncryptionWindow::selectEncryptInputFile);
    connect(encryptOutputBrowseButton, &QPushButton::clicked, this, &EncryptionWindow::selectEncryptOutputDir);
    connect(encryptButton, &QPushButton::clicked, this, &EncryptionWindow::encryptFile);
}

void EncryptionWindow::selectEncryptInputFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Input File");
    if (!fileName.isEmpty()) {
        encryptInputFileEdit->setText(fileName);
    }
}

void EncryptionWindow::selectEncryptOutputDir() {
    QString dirName = QFileDialog::getExistingDirectory(this, "Select Output Directory");
    if (!dirName.isEmpty()) {
        encryptOutputDirEdit->setText(dirName);
    }
}

void EncryptionWindow::processFile(bool encrypting, const QString &key, const QString &inputFile, 
                                   const QString &outputDir) {
    if (key.isEmpty() || inputFile.isEmpty() || outputDir.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please fill in all fields");
        return;
    }

    try {
        std::ifstream inFile(inputFile.toStdString(), std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Cannot open input file");
        }

        std::vector<char> data((std::istreambuf_iterator<char>(inFile)),
                              std::istreambuf_iterator<char>());
        inFile.close();

        // XOR encryption/decryption
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = data[i] ^ key.toStdString()[i % key.length()];
        }

        std::ofstream outFile((outputDir + "/" + QFileInfo(inputFile).fileName()).toStdString(), std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Cannot open output file");
        }
        outFile.write(data.data(), data.size());
        outFile.close();

        QMessageBox::information(this, "Success",
                               QString("File successfully %1ed").arg(encrypting ? "encrypt" : "decrypt"));
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", e.what());
    }
}

void EncryptionWindow::encryptFile() {
    processFile(true, encryptKeyInput->text(), encryptInputFileEdit->text(), encryptOutputDirEdit->text());
}

void EncryptionWindow::decryptFile() {
    processFile(false, decryptKeyInput->text(), decryptInputFileEdit->text(), decryptOutputDirEdit->text());
}

void EncryptionWindow::setupDecryptionTab(QWidget *tab) {
    auto *layout = new QGridLayout(tab);
    
    // Key input
    auto *keyLabel = new QLabel("Decryption Key:", tab);
    decryptKeyInput = new QLineEdit(tab);
    decryptKeyInput->setEchoMode(QLineEdit::Password);
    layout->addWidget(keyLabel, 0, 0);
    layout->addWidget(decryptKeyInput, 0, 1, 1, 2);
    
    // Input file
    auto *inputLabel = new QLabel("Select Encrypted File:", tab);
    decryptInputFileEdit = new QLineEdit(tab);
    decryptInputBrowseButton = new QPushButton("Browse", tab);
    layout->addWidget(inputLabel, 1, 0);
    layout->addWidget(decryptInputFileEdit, 1, 1);
    layout->addWidget(decryptInputBrowseButton, 1, 2);
    
    // Output directory
    auto *outputLabel = new QLabel("Save Decrypted File in:", tab);
    decryptOutputDirEdit = new QLineEdit(tab);
    decryptOutputBrowseButton = new QPushButton("Browse", tab);
    layout->addWidget(outputLabel, 2, 0);
    layout->addWidget(decryptOutputDirEdit, 2, 1);
    layout->addWidget(decryptOutputBrowseButton, 2, 2);
    
    // Decrypt button
    decryptButton = new QPushButton("Decrypt File", tab);
    layout->addWidget(decryptButton, 3, 0, 1, 3);
    
    // Connect signals
    connect(decryptInputBrowseButton, &QPushButton::clicked, this, &EncryptionWindow::selectDecryptInputFile);
    connect(decryptOutputBrowseButton, &QPushButton::clicked, this, &EncryptionWindow::selectDecryptOutputDir);
    connect(decryptButton, &QPushButton::clicked, this, &EncryptionWindow::decryptFile);
}

void EncryptionWindow::selectDecryptInputFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Encrypted File");
    if (!fileName.isEmpty()) {
        decryptInputFileEdit->setText(fileName);
    }
}

void EncryptionWindow::selectDecryptOutputDir() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Output Directory");
    if (!dir.isEmpty()) {
        decryptOutputDirEdit->setText(dir);
    }
} 