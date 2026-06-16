#include <wx/wx.h>
#include <wx/listctrl.h>
#include <sqlite3.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <cstring>
#include <vector>
#include <string>

// Global variable for the derived master key
std::vector<unsigned char> gMasterKey;

// ==================================================================
// Updated OpenSSL AES-256-CBC Encryption Function
bool EncryptAES(const std::string& plaintext,
    const std::vector<unsigned char>& key,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& iv)
{
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    int iv_len = EVP_CIPHER_iv_length(cipher);
    iv.resize(iv_len);
    if (RAND_bytes(iv.data(), iv_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Use the user-derived key instead of a hardcoded one
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int block_size = EVP_CIPHER_block_size(cipher);
    ciphertext.resize(plaintext.size() + block_size);
    int out_len1 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1,
        reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int out_len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// ==================================================================
// Updated OpenSSL AES-256-CBC Decryption Function
bool DecryptAES(const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& iv,
    std::string& plaintext,
    const std::vector<unsigned char>& key)
{
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> out(ciphertext.size() + EVP_CIPHER_block_size(cipher));
    int out_len1 = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &out_len1,
        ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int out_len2 = 0;
    if (EVP_DecryptFinal_ex(ctx, out.data() + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.resize(out_len1 + out_len2);
    plaintext.assign(reinterpret_cast<char*>(out.data()), out.size());
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// ==================================================================
// Dialog for Adding/Editing an Entry
class AddEntryDialog : public wxDialog {
public:
    wxTextCtrl* serviceCtrl;
    wxTextCtrl* usernameCtrl;
    wxTextCtrl* passwordCtrl;

    AddEntryDialog(wxWindow* parent, const wxString& title = "Add New Entry")
        : wxDialog(parent, wxID_ANY, title, wxDefaultPosition, wxSize(300, 250))
    {
        wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

        // Service label and input
        vbox->Add(new wxStaticText(this, wxID_ANY, "Service:"), 0, wxLEFT | wxTOP, 10);
        serviceCtrl = new wxTextCtrl(this, wxID_ANY);
        vbox->Add(serviceCtrl, 0, wxEXPAND | wxALL, 10);

        // Username label and input
        vbox->Add(new wxStaticText(this, wxID_ANY, "Username:"), 0, wxLEFT, 10);
        usernameCtrl = new wxTextCtrl(this, wxID_ANY);
        vbox->Add(usernameCtrl, 0, wxEXPAND | wxALL, 10);

        // Password label and input (hidden)
        vbox->Add(new wxStaticText(this, wxID_ANY, "Password:"), 0, wxLEFT, 10);
        passwordCtrl = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
        vbox->Add(passwordCtrl, 0, wxEXPAND | wxALL, 10);

        // Buttons: Save and Cancel
        wxBoxSizer* btnSizer = new wxBoxSizer(wxHORIZONTAL);
        btnSizer->Add(new wxButton(this, wxID_OK, "Save"), 0, wxALL, 5);
        btnSizer->Add(new wxButton(this, wxID_CANCEL, "Cancel"), 0, wxALL, 5);
        vbox->Add(btnSizer, 0, wxALIGN_CENTER | wxBOTTOM, 10);

        SetSizerAndFit(vbox);
    }
};

// ==================================================================
// Main Application Window
class MainFrame : public wxFrame {
public:
    MainFrame()
        : wxFrame(nullptr, wxID_ANY, "Encrypted Password Manager", wxDefaultPosition, wxSize(600, 400))
    {
        wxPanel* panel = new wxPanel(this);

        // Create a wxListCtrl with columns for Service, Username, and Password
        listCtrl = new wxListCtrl(panel, wxID_ANY, wxDefaultPosition, wxSize(580, 250),
            wxLC_REPORT | wxLC_SINGLE_SEL);
        listCtrl->InsertColumn(0, "Service", wxLIST_FORMAT_LEFT, 200);
        listCtrl->InsertColumn(1, "Username", wxLIST_FORMAT_LEFT, 200);
        listCtrl->InsertColumn(2, "Password", wxLIST_FORMAT_LEFT, 150);

        // Buttons for adding, editing, and deleting entries
        wxBoxSizer* btnSizer = new wxBoxSizer(wxHORIZONTAL);
        wxButton* addBtn = new wxButton(panel, wxID_ADD, "Add");
        wxButton* editBtn = new wxButton(panel, wxID_EDIT, "Edit");
        wxButton* delBtn = new wxButton(panel, wxID_DELETE, "Delete");

        addBtn->Bind(wxEVT_BUTTON, &MainFrame::OnAddClicked, this);
        editBtn->Bind(wxEVT_BUTTON, &MainFrame::OnEditClicked, this);
        delBtn->Bind(wxEVT_BUTTON, &MainFrame::OnDeleteClicked, this);

        btnSizer->Add(addBtn, 0, wxALL, 5);
        btnSizer->Add(editBtn, 0, wxALL, 5);
        btnSizer->Add(delBtn, 0, wxALL, 5);

        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
        mainSizer->Add(listCtrl, 1, wxALL | wxEXPAND, 10);
        mainSizer->Add(btnSizer, 0, wxALIGN_CENTER | wxBOTTOM, 10);

        panel->SetSizer(mainSizer);

        InitDB();
        LoadEntries();
    }

    ~MainFrame() {
        if (db)
            sqlite3_close(db);
    }

private:
    wxListCtrl* listCtrl;
    sqlite3* db = nullptr;

    // ==================================================================
    // Create (or open) the SQLite database and table
    void InitDB() {
        int rc = sqlite3_open("passwords.db", &db);
        if (rc != SQLITE_OK) {
            wxMessageBox("Unable to open database", "Error", wxICON_ERROR);
            return;
        }
        const char* createTableSQL =
            "CREATE TABLE IF NOT EXISTS passwords ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "service TEXT, "
            "username TEXT, "
            "encrypted BLOB, "
            "iv BLOB"
            ");";
        char* errMsg = nullptr;
        rc = sqlite3_exec(db, createTableSQL, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            wxMessageBox(wxString("DB Error: ") + errMsg, "Error", wxICON_ERROR);
            sqlite3_free(errMsg);
        }
    }

    // ==================================================================
    // Populate the list control with entries loaded from the database
    void LoadEntries() {
        listCtrl->DeleteAllItems();
        const char* querySQL = "SELECT id, service, username, encrypted, iv FROM passwords;";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, querySQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            wxMessageBox("Failed to prepare statement", "Error", wxICON_ERROR);
            return;
        }
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const unsigned char* serviceText = sqlite3_column_text(stmt, 1);
            const unsigned char* usernameText = sqlite3_column_text(stmt, 2);
            std::string service = serviceText ? reinterpret_cast<const char*>(serviceText) : "";
            std::string username = usernameText ? reinterpret_cast<const char*>(usernameText) : "";

            // Fetch the encrypted password and IV from the database
            const void* encryptedBlob = sqlite3_column_blob(stmt, 3);
            int encryptedSize = sqlite3_column_bytes(stmt, 3);
            const void* ivBlob = sqlite3_column_blob(stmt, 4);
            int ivSize = sqlite3_column_bytes(stmt, 4);
            std::vector<unsigned char> encrypted, iv;
            if (encryptedBlob && encryptedSize > 0 && ivBlob && ivSize > 0) {
                encrypted.resize(encryptedSize);
                iv.resize(ivSize);
                std::memcpy(encrypted.data(), encryptedBlob, encryptedSize);
                std::memcpy(iv.data(), ivBlob, ivSize);
            }
            std::string password;
            if (!DecryptAES(encrypted, iv, password, gMasterKey))
                password = "Decryption error";

            long index = listCtrl->InsertItem(listCtrl->GetItemCount(), service);
            listCtrl->SetItem(index, 1, username);
            listCtrl->SetItem(index, 2, password);
            // Store the unique id in the item data for later reference
            listCtrl->SetItemData(index, id);
        }
        sqlite3_finalize(stmt);
    }

    // ==================================================================
    // Handler for the "Add" button: insert a new record
    void OnAddClicked(wxCommandEvent&) {
        AddEntryDialog dlg(this);
        if (dlg.ShowModal() == wxID_OK) {
            wxString service = dlg.serviceCtrl->GetValue();
            wxString username = dlg.usernameCtrl->GetValue();
            wxString password = dlg.passwordCtrl->GetValue();

            if (service.IsEmpty() || username.IsEmpty() || password.IsEmpty()) {
                wxMessageBox("All fields must be filled.", "Warning", wxICON_WARNING);
                return;
            }
            std::string plainText = password.ToStdString();
            std::vector<unsigned char> cipherText, iv;
            if (!EncryptAES(plainText, gMasterKey, cipherText, iv)) {
                wxMessageBox("Encryption error.", "Error", wxICON_ERROR);
                return;
            }

            const char* insertSQL = "INSERT INTO passwords (service, username, encrypted, iv) VALUES (?, ?, ?, ?);";
            sqlite3_stmt* stmt = nullptr;
            int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                wxMessageBox("Failed to prepare insert statement", "Error", wxICON_ERROR);
                return;
            }
            sqlite3_bind_text(stmt, 1, service.mb_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, username.mb_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 3, cipherText.data(), static_cast<int>(cipherText.size()), SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                wxMessageBox("Failed to insert data", "Error", wxICON_ERROR);
            }
            sqlite3_finalize(stmt);
            LoadEntries();
        }
    }

    // ==================================================================
    // Handler for the "Edit" button: update an existing record
    void OnEditClicked(wxCommandEvent&) {
        long selected = listCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (selected == -1) {
            wxMessageBox("Select an entry to edit.", "Warning", wxICON_WARNING);
            return;
        }
        // Retrieve the unique id and current field values
        long id = listCtrl->GetItemData(selected);
        wxString currentService = listCtrl->GetItemText(selected, 0);
        wxString currentUsername = listCtrl->GetItemText(selected, 1);
        wxString currentPassword = listCtrl->GetItemText(selected, 2);

        // Pre-populate the dialog with the current data
        AddEntryDialog dlg(this, "Edit Entry");
        dlg.serviceCtrl->SetValue(currentService);
        dlg.usernameCtrl->SetValue(currentUsername);
        dlg.passwordCtrl->SetValue(currentPassword);

        if (dlg.ShowModal() == wxID_OK) {
            wxString newService = dlg.serviceCtrl->GetValue();
            wxString newUsername = dlg.usernameCtrl->GetValue();
            wxString newPassword = dlg.passwordCtrl->GetValue();

            if (newService.IsEmpty() || newUsername.IsEmpty() || newPassword.IsEmpty()) {
                wxMessageBox("All fields must be filled.", "Warning", wxICON_WARNING);
                return;
            }
            std::string plainText = newPassword.ToStdString();
            std::vector<unsigned char> cipherText, iv;
            if (!EncryptAES(plainText, gMasterKey, cipherText, iv)) {
                wxMessageBox("Encryption error.", "Error", wxICON_ERROR);
                return;
            }

            const char* updateSQL = "UPDATE passwords SET service = ?, username = ?, encrypted = ?, iv = ? WHERE id = ?;";
            sqlite3_stmt* stmt = nullptr;
            int rc = sqlite3_prepare_v2(db, updateSQL, -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                wxMessageBox("Failed to prepare update statement", "Error", wxICON_ERROR);
                return;
            }
            sqlite3_bind_text(stmt, 1, newService.mb_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, newUsername.mb_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 3, cipherText.data(), static_cast<int>(cipherText.size()), SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 5, id);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                wxMessageBox("Failed to update data", "Error", wxICON_ERROR);
            }
            sqlite3_finalize(stmt);
            LoadEntries();
        }
    }

    // ==================================================================
    // Handler for the "Delete" button: remove an entry from the database
    void OnDeleteClicked(wxCommandEvent&) {
        long selected = listCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (selected == -1) {
            wxMessageBox("Please select an entry to delete.", "Warning", wxICON_WARNING);
            return;
        }
        long id = listCtrl->GetItemData(selected);
        const char* deleteSQL = "DELETE FROM passwords WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            wxMessageBox("Failed to prepare delete statement", "Error", wxICON_ERROR);
            return;
        }
        sqlite3_bind_int(stmt, 1, id);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            wxMessageBox("Failed to delete entry", "Error", wxICON_ERROR);
        }
        sqlite3_finalize(stmt);
        LoadEntries();
    }
};

// ==================================================================
// wxWidgets Application Class with Master Password Prompt and Key Derivation
class PasswordApp : public wxApp {
public:
    virtual bool OnInit() {
        // Prompt the user for a master password
        wxString masterPassword = wxGetPasswordFromUser("Enter Master Password:", "Master Key Required");
        if (masterPassword.IsEmpty()) {
            wxMessageBox("Master Password cannot be empty. Exiting.", "Error", wxICON_ERROR);
            return false;
        }

        // Derive a 256-bit key from the master password using PBKDF2
        std::string masterPwdStr = masterPassword.ToStdString();
        unsigned char keyOut[32];
        // Use a fixed salt for demonstration purposes (in production, use a proper random salt)
        const unsigned char* salt = reinterpret_cast<const unsigned char*>("YourFixedSalt123");
        if (PKCS5_PBKDF2_HMAC(masterPwdStr.c_str(),
            static_cast<int>(masterPwdStr.size()),
            salt,
            static_cast<int>(strlen(reinterpret_cast<const char*>(salt))),
            100000,  // iterations
            EVP_sha256(),
            32,      // key length
            keyOut) != 1)
        {
            wxMessageBox("Key derivation failed", "Error", wxICON_ERROR);
            return false;
        }
        // Store the derived key in the global variable for use in encryption/decryption
        gMasterKey.assign(keyOut, keyOut + 32);

        // Create and show the main window
        MainFrame* frame = new MainFrame();
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(PasswordApp);