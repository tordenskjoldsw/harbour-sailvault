#ifndef DATABASES_H
#define DATABASES_H

#include <QObject>
#include <QString>
#include <QStringList>

// The databases in the app's private data directory, which Sailjail keeps
// from other sandboxed apps. A database is known by its name: its file is
// databases/<name>.kdbx, its key file, if it has one, keyfiles/<name>.key.
class Databases : public QObject
{
    Q_OBJECT

public:
    explicit Databases(QObject *parent = nullptr);

    // Empty when the name is not valid.
    static QString databasePath(const QString &name);
    static QString keyFilePath(const QString &name);
    static QString backupDirectory();
    // Prepares storing a new database under name: creates the directories
    // and removes a key file an interrupted add left without its database.
    // Returns StatusFileExists when the name is taken.
    static int claim(const QString &name);

    // Names that are not empty, have no surrounding spaces, do not start
    // with a dot, contain no slash and have at most 100 characters.
    Q_INVOKABLE static bool isValidName(const QString &name);
    Q_INVOKABLE static bool exists(const QString &name);
    Q_INVOKABLE static bool hasKeyFile(const QString &name);
    // Sorted ignoring case.
    Q_INVOKABLE static QStringList names();
};

#endif // DATABASES_H
