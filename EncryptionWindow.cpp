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
    setWindowTitle("Encryptor");
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
    QString fileName = QFileDialog::getOpenFileName(this, 
        "Select File to Encrypt",
        QString(),
        "All Files (*.*);;Text Files (*.txt);;Documents (*.doc *.docx *.pdf)");
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
        // Calculate original file hash for encryption
        QString originalHash;
        if (encrypting) {
            originalHash = calculateFileHash(inputFile);
        }

        std::ifstream inFile(inputFile.toStdString(), std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Cannot open input file");
        }

        std::vector<char> data((std::istreambuf_iterator<char>(inFile)),
                              std::istreambuf_iterator<char>());
        inFile.close();

        // Add hash and extension to encrypted data for validation
        if (encrypting) {
            QString originalExt = QFileInfo(inputFile).suffix();
            QString header = "ENCRYPTED:" + originalHash + ":" + originalExt + ":";
            std::string headerStr = header.toStdString();
            data.insert(data.begin(), headerStr.begin(), headerStr.end());
        }

        // XOR encryption/decryption
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = data[i] ^ key.toStdString()[i % key.length()];
        }

        QString originalExt;
        if (!encrypting) {
            // Verify decryption by checking the header
            std::string dataStr(data.begin(), data.end());
            QString decryptedData = QString::fromStdString(dataStr);
            
            if (!decryptedData.startsWith("ENCRYPTED:")) {
                throw std::runtime_error("Invalid decryption key or corrupted file");
            }

            // Parse header sections
            QStringList headerParts = decryptedData.split(":", Qt::KeepEmptyParts);
            if (headerParts.size() < 4) {
                throw std::runtime_error("Corrupted file header");
            }

            originalExt = headerParts[2];
            
            // Remove header from data
            int headerEnd = decryptedData.indexOf(":", decryptedData.indexOf(":", 10) + 1);
            data.erase(data.begin(), data.begin() + headerEnd + 1);
        }

        QString outputPath = outputDir + "/" + QFileInfo(inputFile).fileName();
        if (encrypting) {
            QString baseName = QFileInfo(outputPath).completeBaseName();
            outputPath = outputDir + "/" + baseName + ".encrypted";
        } else {
            QString baseName = QFileInfo(outputPath).completeBaseName();
            baseName = baseName.replace(".encrypted", "");
            outputPath = outputDir + "/" + baseName + "." + originalExt;
        }

        std::ofstream outFile(outputPath.toStdString(), std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Cannot open output file");
        }
        outFile.write(data.data(), data.size());
        outFile.close();

        if (!encrypting) {
            // Verify the decrypted file
            QString decryptedHash = calculateFileHash(outputPath);
            if (decryptedHash.isEmpty()) {
                throw std::runtime_error("Failed to verify decrypted file");
            }
        }

        if (encrypting) {
            // After successful encryption we delete the original file
            secureDelete(inputFile);
        }

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

void EncryptionWindow::secureDelete(const QString &filePath) {
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        qint64 size = file.size();
        QByteArray randomData(1024, 0);
        for (qint64 i = 0; i < size; i += 1024) {
            for (int j = 0; j < randomData.size(); ++j) {
                randomData[j] = QRandomGenerator::global()->generate();
            }
            file.write(randomData);
        }
        file.close();
    }
    file.remove();
}

QString EncryptionWindow::calculateFileHash(const QString &filePath) {
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly)) {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(&file);
        return hash.result().toHex();
    }
    return QString();
}

void EncryptionWindow::createBackup(const QString &filePath) {
    QFile::copy(filePath, filePath + ".backup");
}