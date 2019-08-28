DROP TABLE IF EXISTS users;

CREATE TABLE users(
    id INTEGER primary key autoincrement UNIQUE,
    user_name TEXT(100) UNIQUE not null, 
    user_password TEXT(100) not null,
    rights TEXT(3) not NULL
);

INSERT INTO users
    (id, user_name, user_password, rights)
VALUES
    (null, 'admin', 'admin','crud');
INSERT into users
    (id, user_name, user_password, rights)
VALUES
    (null, 'u1', 4321, 'crud');

