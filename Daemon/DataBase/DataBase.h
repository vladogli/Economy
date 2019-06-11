#ifndef DATABASE_H
#define DATABASE_H
#include <sqlite3.h>
class DataBase {
    sqlite3 *db;
    int rc;
public:
    enum ERRORS {
        ERROR_CANNOT_OPEN_FILE
    };
    DataBase(::std::string);
    ~DataBase();
};
#include "DataBase.cpp"
#endif