DROP TABLE IF EXISTS users;

CREATE TABLE users(
    id INTEGER primary key autoincrement,
    user_name TEXT(32) not null, 
    user_password TEXT(32) not null,
    rights_C boolean not null, 
    rights_R boolean not null,
    rights_U boolean not null,
    rights_D boolean not null
);

INSERT INTO users
    (id, user_name, user_password, rights_C,rights_R,rights_U,rights_D)
VALUES
    (null, 'admin', 'admin',1,1,1,1);
INSERT into users
    (id, user_name, user_password, rights_C,rights_R,rights_U,rights_D)
VALUES
    (null, 'u1', 4321,0,0,0,0);

