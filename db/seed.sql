CREATE TABLE helo_users (
    id SERIAL PRIMARY KEY,
    username varchar(255) NOT NULL,
    password varchar(255) NOT NULL,
    profile_pic text
);

CREATE TABLE helo_posts (
    id SERIAL PRIMARY KEY,
    title varchar(45) NOT NULL,
    content text,
    img text,
    author_id integer references helo_users(id),
    date_created timestamp
);