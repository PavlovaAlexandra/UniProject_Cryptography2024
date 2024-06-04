#include "db.h"
#include <iostream>
//create the database
Database::Database(const std::string& dbName) {
    
    if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error: cannot open the database: " << sqlite3_errmsg(db) << "\n";
        db = nullptr;
    }
}

Database::Database() {
    
    if (db) {
        sqlite3_close(db);
    }
}
//execute the given query
bool Database::executeQuery(const std::string& query) {
    
    char* errMsg = nullptr;
    
    if (sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error on executing query: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }
    
    return true;
}

bool Database::createUserTable() {
    
    std::string query = "CREATE TABLE IF NOT EXISTS users ("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "email TEXT UNIQUE NOT NULL,"
                        "nickname TEXT NOT NULL,"
                        "password TEXT NOT NULL,"
                        "salt TEXT NOT NULL);";
    
    return executeQuery(query);
}

bool Database::createMessageTable() {
    
    std::string query = "CREATE TABLE IF NOT EXISTS messages ("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "title TEXT NOT NULL,"
                        "author TEXT NOT NULL,"
                        "body TEXT NOT NULL);";
    
    return executeQuery(query);
}
//insert the user after the registration phase
bool Database::addUser(const std::string& email, const std::string& nickname, const std::string& hashedPassword, const std::string& salt) {
    
    std::string query = "INSERT INTO users (email, nickname, password, salt) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    
    if (!executeStatement(query, stmt)) return false;

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, nickname.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, hashedPassword.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, salt.c_str(), -1, SQLITE_STATIC);

    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return result;
}
//insert the message after typing
bool Database::addMessage(const std::string& title, const std::string& author, const std::string& body) {

    std::string query = "INSERT INTO messages (title, author, body) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (!executeStatement(query, stmt)) return false;

    sqlite3_bind_text(stmt, 1, title.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, author.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, body.c_str(), -1, SQLITE_STATIC);

    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return result;
}
//get the password and the salt of the user in order to be verified in login phase
std::map<std::string, std::string> Database::getUserCredentials(const std::string& nickname) {

    std::string query = "SELECT password, salt FROM users WHERE nickname = ?;";
    sqlite3_stmt* stmt;
    std::map<std::string, std::string> result;
    
    if (executeStatement(query, stmt)) {
        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result["password"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            result["salt"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }

    return result;
}
//get the list of the last n messages 
std::vector<std::map<std::string, std::string>> Database::getMessages(int limit) {

    std::string query = "SELECT * FROM messages ORDER BY id DESC LIMIT ?;";
    sqlite3_stmt* stmt;
    std::vector<std::map<std::string, std::string>> results;

    if (executeStatement(query, stmt)) {
        sqlite3_bind_int(stmt, 1, limit);
        results = fetchResults(stmt);
        sqlite3_finalize(stmt);
    }
    return results;
}
//get all the messages written by one user
std::vector<std::map<std::string, std::string>> Database::getMessagesByAuthor(const std::string& author) {

    std::string query = "SELECT * FROM messages WHERE author = ?;";
    sqlite3_stmt* stmt;
    std::vector<std::map<std::string, std::string>> results;

    if (executeStatement(query, stmt)) {
        sqlite3_bind_text(stmt, 1, author.c_str(), -1, SQLITE_STATIC);
        results = fetchResults(stmt);
        sqlite3_finalize(stmt);
    }

    return results;
}

std::string Database::getNickname(const std::string& nickname) {

    std::string query = "SELECT nickname FROM users WHERE nickname = ?;";
    sqlite3_stmt* stmt;
    std::string result;
    
    if (executeStatement(query, stmt)) {
        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    return result;
}
//execute the statement of the query: more secure than executeQuery
bool Database::executeStatement(const std::string& query, sqlite3_stmt*& stmt) {

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error: Failed to prepare SQL statement: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    return true;
}
//retrieves the results of an executed statement
std::vector<std::map<std::string, std::string>> Database::fetchResults(sqlite3_stmt* stmt) {

    std::vector<std::map<std::string, std::string>> results;
    int numCols = sqlite3_column_count(stmt);

    while (sqlite3_step(stmt) == SQLITE_ROW) { //iterate over the result rows
        std::map<std::string, std::string> row;
        for (int i = 0; i < numCols; ++i) {
            std::string colName = sqlite3_column_name(stmt, i); //get the column name
            std::string colValue = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i)); //get the column values
            row[colName] = colValue;
        }
        results.push_back(row);
    }
    return results;
}