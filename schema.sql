BEGIN TRANSACTION;
CREATE TABLE users (
    id int unique NOT NULL PRIMARY KEY,
    name text,
    gecos text,
    password text,
    hash text
);
COMMIT;
