#include "../h/import_export.h"
#include "../h/mmap_utils.h"
#include <json/json.h>
#include <stdexcept>

// Экспортирует пароли в JSON-файл через mmap
// TODO: Добавить шифрование JSON с использованием master_key
void ImportExport::exportPasswords(const std::string &buffer_file, const std::vector<PasswordEntry> &entries) {
    Json::Value root(Json::arrayValue);
    for (const auto& entry : entries) {
        Json::Value item;
        item["description"] = entry.description;
        item["login"] = entry.login;
        item["password"] = entry.password; // Пароль уже расшифрован
        root.append(item);
    }

    Json::StreamWriterBuilder builder;
    std::string json_data = Json::writeString(builder, root);
    MMAPUtils::writeImportExportBuffer(buffer_file, json_data);
}

// Импортирует пароли из JSON-файла через mmap
// TODO: Добавить расшифровку JSON с использованием master_key
std::vector<PasswordEntry> ImportExport::importPasswords(const std::string& buffer_file) {
    std::string json_data = MMAPUtils::readImportExportBuffer(buffer_file);
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    std::string errors;

    if (!reader->parse(json_data.c_str(), json_data.c_str() + json_data.size(), &root, &errors)) {
        throw std::runtime_error("Failed to parse JSON: " + errors);
    }

    std::vector<PasswordEntry> entries;
    for (const auto& item : root) {
        PasswordEntry entry;
        entry.description = item["description"].asString();
        entry.login = item["login"].asString();
        entry.password = item["password"].asString(); // Будет зашифрован при добавлении
        entries.push_back(entry);
    }

    return entries;
}
