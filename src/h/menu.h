#ifndef MENU_H
#define MENU_H

#include "database.h"

class Menu {
public:
    Menu(const std::string& db_path, const std::string& master_password);
    void run();

private:
    Database db;
};

#endif