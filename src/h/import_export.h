#ifndef IMPORT_EXPORT_H
#define IMPORT_EXPORT_H

#include <string>
#include <vector>
#include "../h/database.h"
#include "crypto.h"

class ImportExport {
public:
    static void
    exportPasswords(const std::string &buffer_file, const std::vector<PasswordEntry> &entries);
    static std::vector<PasswordEntry> importPasswords(const std::string& buffer_file);
};

#endif // IMPORT_EXPORT_H