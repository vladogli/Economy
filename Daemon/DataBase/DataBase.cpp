#include "DataBase.h"
#include <iostream>
#include <sqlite3.h>
DataBase::DataBase(::std::string dbname){
        rc = sqlite3_open(dbname.c_str(), &db);
        if(rc) {
            ::std::cout << "DATABASE ERROR. Can't open database: " << sqlite3_errmsg(db) << "\n";
            throw ::DataBase::ERRORS::ERROR_CANNOT_OPEN_FILE;
        } 
        else {
            ::std::cout << "Database was opened successfully.\n";
        }
}
DataBase::~DataBase() {
    sqlite3_close(db);
}