DROP TABLE IF EXISTS users;

CREATE TABLE users(
    id INTEGER primary key NOT NULL autoincrement,
    user_name TEXT(100) UNIQUE not null, 
    user_password TEXT(100) not null,
    rights TEXT(3) not NULL
);

INSERT INTO users
VALUES
    (null, 'admin', '$5$rounds=535000$fdBjgNbCwhFr3dQX$wO.xQyaGfEL2pOpasecCP7FwcsiWr7CPt1l/Su0BYm4','crud');
