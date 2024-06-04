#ifndef DB_H
#define DB_H

#include <sqlite3.h>
#include <string>
#include <vector>
#include <map>

class Database {
public:
    Database(const std::string& dbName);
    Database();

    bool executeQuery(const std::string& query);
    bool createUserTable();
    bool createMessageTable();
    bool addUser(const std::string& email, const std::string& nickname, const std::string& hashedPassword, const std::string& salt);
    bool addMessage(const std::string& title, const std::string& author, const std::string& body);
    
    std::map<std::string, std::string> getUserCredentials(const std::string& nickname);
    std::vector<std::map<std::string, std::string>> getMessages(int limit);
    std::vector<std::map<std::string, std::string>> getMessagesByAuthor(const std::string& author);
    std::string getNickname(const std::string& nickname);

private:
    sqlite3* db;
    bool executeStatement(const std::string& query, sqlite3_stmt*& stmt);
    std::vector<std::map<std::string, std::string>> fetchResults(sqlite3_stmt* stmt);
};

#endif // DB_H
