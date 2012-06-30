drop table if exists users;
create table users (
  user_id integer primary key autoincrement,
  username string not null,
  email string not null,
  pw_hash string not null
);

drop table if exists stories;
create table stories (
  story_id integer primary key autoincrement,
  author_id integer not null,
  title string not null,
  text string not null,
  pub_date integer
);
